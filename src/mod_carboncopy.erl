%%%----------------------------------------------------------------------
%%% File    : mod_carboncopy.erl
%%% Author  : Eric Cestari <ecestari@process-one.net>
%%% Purpose : Message Carbons XEP-0280 0.8
%%% Created : 5 May 2008 by Mickael Remond <mremond@process-one.net>
%%% Usage   : Add `mod_carboncopy` to the `modules` section of mongooseim.toml
%%%
%%%
%%% ejabberd, Copyright (C) 2002-2014   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------
-module (mod_carboncopy).
-author ('ecestari@process-one.net').
-xep([{xep, 280}, {version, "0.6"}]).
-xep([{xep, 280}, {version, "0.13.1"}]).
-behaviour(gen_mod).
-behaviour(mongoose_module_metrics).

%% API
-export([start/2,
         stop/1,
         config_spec/0,
         is_carbon_copy/1,
         classify_packet/1]).

%% Hooks
-export([user_send_packet/4,
         user_receive_packet/5,
         iq_handler2/4,
         iq_handler1/4,
         remove_connection/5
        ]).

-define(CC_KEY, 'cc').
-define(CC_DISABLED, undefined).

-include("mongoose.hrl").
-include("jlib.hrl").
-include("session.hrl").
-include("mongoose_config_spec.hrl").

-type classification() :: 'ignore' | 'forward'.

is_carbon_copy(Packet) ->
    case xml:get_subtag(Packet, <<"sent">>) of
        #xmlel{name = <<"sent">>, attrs = AAttrs}  ->
            case xml:get_attr_s(<<"xmlns">>, AAttrs) of
                ?NS_CC_2 -> true;
                ?NS_CC_1 -> true;
                _ -> false
            end;
        _ -> false
    end.

start(Host, Opts) ->
    %% execute disable/enable actions in the c2s process itself
    IQDisc = gen_mod:get_opt(iqdisc, Opts, no_queue),
    mod_disco:register_feature(Host, ?NS_CC_1),
    mod_disco:register_feature(Host, ?NS_CC_2),
    ejabberd_hooks:add(unset_presence_hook, Host, ?MODULE, remove_connection, 10),
    ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 89),
    ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, user_receive_packet, 89),
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host, ?NS_CC_2, ?MODULE, iq_handler2, IQDisc),
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host, ?NS_CC_1, ?MODULE, iq_handler1, IQDisc).

stop(Host) ->
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_CC_1),
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_CC_2),
    mod_disco:unregister_feature(Host, ?NS_CC_2),
    mod_disco:unregister_feature(Host, ?NS_CC_1),
    ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, user_send_packet, 89),
    ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE, user_receive_packet, 89),
    ejabberd_hooks:delete(unset_presence_hook, Host, ?MODULE, remove_connection, 10).

-spec config_spec() -> mongoose_config_spec:config_section().
config_spec() ->
    #section{items = #{<<"iqdisc">> => mongoose_config_spec:iqdisc()}}.

iq_handler2(From, To, Acc, IQ) ->
    iq_handler(From, To, Acc, IQ, ?NS_CC_2).
iq_handler1(From, To, Acc, IQ) ->
    iq_handler(From, To, Acc, IQ, ?NS_CC_1).

iq_handler(From, _To,  Acc, #iq{type = set, sub_el = #xmlel{name = Operation,
                                                       children = []}} = IQ, CC) ->
    ?LOG_DEBUG(#{what => cc_iq_received, acc => Acc}),
    Result = case Operation of
                 <<"enable">> ->
                     enable(From, CC);
                 <<"disable">> ->
                     disable(From)
             end,
    case Result of
        ok ->
            ?LOG_DEBUG(#{what => cc_iq_result, acc => Acc}),
            {Acc, IQ#iq{type=result, sub_el=[]}};
        {error, Reason} ->
            ?LOG_WARNING(#{what => cc_iq_failed, acc => Acc, reason => Reason}),
            {Acc, IQ#iq{type=error, sub_el = [mongoose_xmpp_errors:bad_request()]}}
    end;

iq_handler(_From, _To, Acc, IQ, _CC) ->
    {Acc, IQ#iq{type=error, sub_el = [mongoose_xmpp_errors:not_allowed()]}}.

user_send_packet(Acc, From, To, Packet) ->
    check_and_forward(From, To, Packet, sent),
    Acc.

user_receive_packet(Acc, JID, _From, To, Packet) ->
    check_and_forward(JID, To, Packet, received),
    Acc.

% Check if the traffic is local.
% Modified from original version:
% - registered to the user_send_packet hook, to be called only once even for multicast
% - do not support "private" message mode, and do not modify the original packet in any way
% - we also replicate "read" notifications
-spec check_and_forward(jid:jid(), jid:jid(), exml:element(), sent | received) -> ok | stop.
check_and_forward(JID, To, #xmlel{name = <<"message">>} = Packet, Direction) ->
    case classify_packet(Packet) of
        ignore -> stop;
        forward -> send_copies(JID, To, Packet, Direction)
    end;
check_and_forward(_JID, _To, _Packet, _) -> ok.

-spec classify_packet(exml:element()) -> classification().
classify_packet(Packet) ->
    is_private(Packet).

-spec is_private(exml:element()) -> classification().
is_private(Packet) ->
    case exml_query:subelement_with_name_and_ns(Packet, <<"private">>, ?NS_CC_2) of
        undefined -> is_no_copy(Packet);
        _ -> ignore
    end.

-spec is_no_copy(exml:element()) -> classification().
is_no_copy(Packet) ->
    case exml_query:subelement_with_name_and_ns(Packet, <<"no-copy">>, ?NS_HINTS) of
        undefined -> is_chat(Packet);
        _ -> ignore
    end.

-spec is_chat(exml:element()) -> classification().
is_chat(Packet) ->
    case exml_query:attr(Packet, <<"type">>, <<"normal">>) of
        <<"normal">> -> contains_body(Packet);
        <<"chat">> -> is_not_received_nor_sent(Packet);
        <<"groupchat">> -> ignore;
        _ -> is_muc(Packet)
    end.

%% TODO: other muc rules?
-spec is_muc(exml:element()) -> classification().
is_muc(Packet) ->
    case exml_query:subelement_with_name_and_ns(Packet, <<"x">>, ?NS_MUC_USER) of
        undefined -> forward;
        _ -> is_not_received_nor_sent(Packet)
    end.

-spec contains_body(exml:element()) -> classification().
contains_body(Packet) ->
    case exml_query:subelement(Packet, <<"body">>) of
        undefined -> ignore;
        _ -> forward
    end.

-spec is_not_received_nor_sent(exml:element()) -> classification().
is_not_received_nor_sent(Packet) ->
    case exml_query:subelement_with_name_and_ns(Packet, <<"received">>, ?NS_CC_2) of
        undefined -> is_not_sent(Packet);
        _ -> ignore
    end.

-spec is_not_sent(exml:element()) -> classification().
is_not_sent(Packet) ->
    case exml_query:subelement_with_name_and_ns(Packet, <<"sent">>, ?NS_CC_2) of
        undefined -> forward;
        _ -> ignore
    end.

%% TODO: forwardeds?

remove_connection(Acc, LUser, LServer, LResource, _Status) ->
    JID = jid:make_noprep(LUser, LServer, LResource),
    disable(JID),
    Acc.


%%
%% Internal
%%

%% If the original user is the only resource in the list of targets that means
%% that he/she must have already received the message via normal routing:
drop_singleton_jid(JID, [{JID, _CCVER}]) -> [];
drop_singleton_jid(_JID, Targets)        -> Targets.

is_bare_to(Direction, To) ->
    case {Direction, To} of
        {received, #jid{lresource = <<>>}} -> true;
        _ -> false
    end.

max_prio(PrioRes) ->
    case catch lists:max(PrioRes) of
        {Prio, _Res} -> Prio;
        _ -> 0
    end.

is_max_prio(MaxPrio, Res, PrioRes) ->
    lists:member({MaxPrio, Res}, PrioRes).

jids_minus_max_priority_resources(JID, CCResList, PrioRes) ->
    MaxPrio = max_prio(PrioRes),
    [ {jid:replace_resource(JID, CCRes), CCVersion}
      || {CCVersion, CCRes} <- CCResList, not is_max_prio(MaxPrio, CCRes, PrioRes) ].

jids_minus_specific_resource(#jid{lresource = R} = JID, CCResList) ->
    [ {jid:replace_resource(JID, CCRes), CCVersion}
      || {CCVersion, CCRes} <- CCResList, CCRes =/= R ].

%% TODO: improve
targets(JID, To, Direction) ->
    AllSessions = ejabberd_sm:get_raw_sessions(JID),
    CCResList = filter_cc_enabled_resources(AllSessions),
    PrioRes = filter_priority_resources(AllSessions),
    Targets0 = case is_bare_to(Direction, To) of
                  true -> jids_minus_max_priority_resources(JID, CCResList, PrioRes);
                  _    -> jids_minus_specific_resource(JID, CCResList)
              end,
    Targets = drop_singleton_jid(JID, Targets0),
    ?LOG_DEBUG(#{what => cc_send_copies,
                 targets => Targets, resources => PrioRes, ccenabled => CCResList}),
    Targets.

%% Direction = received | sent <received xmlns='urn:xmpp:carbons:1'/>
-spec send_copies(jid:jid(), jid:jid(), exml:element(), sent | received) -> ok.
send_copies(JID, To, Packet, Direction) ->
    Targets = targets(JID, To, Direction),
    lists:foreach(fun({Dest, Version}) ->
                          ?LOG_DEBUG(#{what => cc_forwarding,
                                       user => JID#jid.luser, server => JID#jid.lserver,
                                       resource => JID#jid.lresource, exml_packet => Packet}),
                          Sender = jid:to_bare(JID),
                          New = build_forward_packet(JID, Packet, Sender, Dest, Direction, Version),
                          ejabberd_router:route(Sender, Dest, New)
                  end, Targets).

build_forward_packet(JID, Packet, Sender, Dest, Direction, Version) ->
    % The wrapping message SHOULD maintain the same 'type' attribute value;
    Type = exml_query:attr(Packet, <<"type">>, <<"normal">>),
    #xmlel{name = <<"message">>,
           attrs = [{<<"xmlns">>, <<"jabber:client">>},
                    {<<"type">>, Type},
                    {<<"from">>, jid:to_binary(Sender)},
                    {<<"to">>, jid:to_binary(Dest)}],
           children = carbon_copy_children(Version, JID, Packet, Direction)}.

carbon_copy_children(?NS_CC_1, JID, Packet, Direction) ->
    [ #xmlel{name = atom_to_binary(Direction, utf8),
             attrs = [{<<"xmlns">>, ?NS_CC_1}]},
      #xmlel{name = <<"forwarded">>,
             attrs = [{<<"xmlns">>, ?NS_FORWARD}],
             children = [complete_packet(JID, Packet, Direction)]} ];
carbon_copy_children(?NS_CC_2, JID, Packet, Direction) ->
    [ #xmlel{name = atom_to_binary(Direction, utf8),
             attrs = [{<<"xmlns">>, ?NS_CC_2}],
             children = [ #xmlel{name = <<"forwarded">>,
                                 attrs = [{<<"xmlns">>, ?NS_FORWARD}],
                                 children = [complete_packet(JID, Packet, Direction)]} ]} ].

enable(JID, CC) ->
    ?LOG_INFO(#{what => cc_enable,
                user => JID#jid.luser, server => JID#jid.lserver}),
    KV = {?CC_KEY, cc_ver_to_int(CC)},
    case ejabberd_sm:store_info(JID, KV) of
        {ok, KV} -> ok;
        {error, _} = Err -> Err
    end.

disable(JID) ->
    ?LOG_INFO(#{what => cc_disable,
                user => JID#jid.luser, server => JID#jid.lserver}),
    KV = {?CC_KEY, ?CC_DISABLED},
    case ejabberd_sm:store_info(JID, KV) of
        {error, offline} -> ok;
        {ok, KV} -> ok;
        Err -> {error, Err}
    end.

complete_packet(From, #xmlel{name = <<"message">>, attrs = OrigAttrs} = Packet, sent) ->
    %% if this is a packet sent by user on this host, then Packet doesn't
    %% include the 'from' attribute. We must add it.
    Attrs = lists:keystore(<<"xmlns">>, 1, OrigAttrs, {<<"xmlns">>, <<"jabber:client">>}),
    case proplists:get_value(<<"from">>, Attrs) of
        undefined ->
            Packet#xmlel{attrs = [{<<"from">>, jid:to_binary(From)} | Attrs]};
        _ ->
            Packet#xmlel{attrs = Attrs}
    end;

complete_packet(_From, #xmlel{name = <<"message">>, attrs=OrigAttrs} = Packet, received) ->
    Attrs = lists:keystore(<<"xmlns">>, 1, OrigAttrs, {<<"xmlns">>, <<"jabber:client">>}),
    Packet#xmlel{attrs = Attrs}.

filter_cc_enabled_resources(AllSessions) ->
    lists:filtermap(fun fun_filter_cc_enabled_resource/1, AllSessions).

fun_filter_cc_enabled_resource(Session = #session{usr = {_, _, R}}) ->
    case mongoose_session:get_info(Session, ?CC_KEY, undefined) of
        {?CC_KEY, V} when is_integer(V) andalso V =/= ?CC_DISABLED ->
            {true, {cc_ver_from_int(V), R}};
        _ ->
            false
    end.

filter_priority_resources(AllSessions) ->
    lists:filtermap(fun fun_filter_priority_resources/1, AllSessions).

fun_filter_priority_resources(#session{usr = {_, _, R}, priority = P})
  when is_integer(P) ->
    {true, {P, R}};
fun_filter_priority_resources(_) ->
    false.

cc_ver_to_int(?NS_CC_1) -> 1;
cc_ver_to_int(?NS_CC_2) -> 2.

cc_ver_from_int(1) -> ?NS_CC_1;
cc_ver_from_int(2) -> ?NS_CC_2.
