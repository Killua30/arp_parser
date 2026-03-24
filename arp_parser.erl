-module(arp_parser).
-export([parse/1, test/0]).

-record(arp_packet, {
    htype,
    ptype,
    hsize,
    psize,
    op,
    sha,
    spa,
    tha,
    tpa
}).

parse(Binary) ->
    <<HType:16, PType:16, HSize:8, PSize:8, Op:16,
      SHA:HSize/binary, SPA:PSize/binary,
      THA:HSize/binary, TPA:PSize/binary>> = Binary,
    Arp = #arp_packet{
        htype = HType,
        ptype = PType,
        hsize = HSize,
        psize = PSize,
        op = Op,
        sha = SHA,
        spa = SPA,
        tha = THA,
        tpa = TPA
    },
    print_arp(Arp),
    ok.

print_arp(#arp_packet{
    htype = HType,
    ptype = PType,
    hsize = HSize,
    psize = PSize,
    op = Op,
    sha = SHa,
    spa = SPa,
    tha = THa,
    tpa = TPa
}) ->
    io:format("ARP Packet:~n"),
    io:format("  Hardware type: ~p~n", [HType]),
    io:format("  Protocol type: ~p~n", [PType]),
    io:format("  Hardware size: ~p~n", [HSize]),
    io:format("  Protocol size: ~p~n", [PSize]),
    io:format("  Operation: ~p~n", [Op]),
    io:format("  Sender MAC address: ~s~n", [format_mac(SHa)]),
    io:format("  Sender IP address: ~s~n", [format_ip(SPa)]),
    io:format("  Target MAC address: ~s~n", [format_mac(THa)]),
    io:format("  Target IP address: ~s~n", [format_ip(TPa)]).

format_mac(Bin) ->
    HexList = [io_lib:format("~2.16.0B", [B]) || <<B:8>> <= Bin],
    string:join(HexList, ":").

format_ip(Bin) ->
    DecList = [io_lib:format("~B", [B]) || <<B:8>> <= Bin],
    string:join(DecList, ".").

test() ->
    TestPacket = <<
        16#00, 16#01, 16#08, 16#00, 16#06, 16#04, 16#00, 16#01,
        16#08, 16#00, 16#27, 16#12, 16#34, 16#56, 16#C0, 16#A8,
        16#01, 16#01, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
        16#C0, 16#A8, 16#01, 16#02
    >>,
    parse(TestPacket).