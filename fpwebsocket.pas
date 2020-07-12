{ Websocket (75,76,7,8,13) client/server implementation

  Copyright (C) 2020 Red_prig

  This library is free software; you can redistribute it and/or modify it
  under the terms of the GNU Library General Public License as published by
  the Free Software Foundation; either version 2 of the License, or (at your
  option) any later version with the following modification:

  As a special exception, the copyright holders of this library give you
  permission to link this library with independent modules to produce an
  executable, regardless of the license terms of these independent modules,and
  to copy and distribute the resulting executable under terms of your choice,
  provided that you also meet, for each linked independent module, the terms
  and conditions of the license of that module. An independent module is a
  module which is not derived from or based on this library. If you modify
  this library, you may extend this exception to your version of the library,
  but you are not obligated to do so. If you do not wish to do so, delete this
  exception statement from your version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public License
  for more details.
}

unit fpWebsocket;

{$mode objfpc}{$H+}

interface

uses
 SysUtils,sha1,md5,mtRandom,fpURI;

const
 WS_ERR_CLOSED=1000;
 WS_ERR_PROTOC=1002;
 WS_ERR_UNSUPP=1003;
 WS_ERR_OPENED=1005;
 WS_ERR_HALTED=1006;
 WS_ERR_I_DATA=1007;
 WS_ERR_POLICY=1008;
 WS_ERR_TO_BIG=1009;
 WS_ERR_NEGEXT=1010;
 WS_ERR_INTERN=1011;

 WS_FLAG_TXT=$1;
 WS_FLAG_FIN=$2;
 WS_FLAG_SRV=$4;
 WS_FLAG_HIX=$8;

 WS_CB_ERR=-1;
 WS_CB_FIN=0;
 WS_CB_PAU=1;
 WS_CB_CON=2;

 WS_OPT_URL=0;
 WS_OPT_ORG=1;
 WS_OPT_PRT=2;

Type
 size_t = NativeUInt;
 ssize_t = NativeInt;

 // (75,76,7,8,13);

 TfpWebsocket_version=(vSec,v76,v7,v8,v13);
 TfpWebsocket_versions=Set of TfpWebsocket_version;

 PfpWebsocket_handshake=^TfpWebsocket_handshake;
 TfpWebsocket_handshake=packed object
  private
   type
    _TStrVal=object
     FStr:PChar;
     FLen:SizeUInt;
    end;
   var
    Host,
    Path,
    Location,
    origin:RawByteString;
    key1,key2,key3:RawByteString;
    protocols:RawByteString;
    extensions:RawByteString;
    versions:TfpWebsocket_versions;
    version:Byte;
    state:ShortInt;
    recv:packed record
     state:Byte;
     LastName,
     LastValue:_TStrVal;
    end;
 end;

 Pheaders_nv=^Theaders_nv;
 Theaders_nv=record
  name    :PAnsiChar;
  value   :PAnsiChar;
  namelen :size_t;
  valuelen:size_t;
  flags   :uint8;
 end;

 PfpWebsocket_session=^TfpWebsocket_session;

 TWebsocket_message_callback=function(session:PfpWebsocket_session;data:Pointer;len:size_t;flags:size_t):ssize_t;

 TfuncFree=Function(p:pointer):SizeUInt;

 Pio_block=^Tio_block;
 Tio_block=record
  data:Pointer;
  len :SizeUInt;
  free:TfuncFree;
  user:Pointer;
 end;

 TWebsocket_alloc_chunk_callback=function(session:PfpWebsocket_session;len:size_t):Tio_block;

 PfpWebsocket_data_provider=^TfpWebsocket_data_provider;

 TfpWebsocket_data_source_cb=function(session:PfpWebsocket_session;
                                      source:PfpWebsocket_data_provider;
                                      frame_len:size_t;
                                      block:Pio_block):ssize_t;

 TfpWebsocket_close_source_cb=function(session:PfpWebsocket_session;
                                       source:PfpWebsocket_data_provider):ssize_t;


 TfpWebsocket_data_provider=record
  data:Pointer;
  user:Pointer;
  close_cb:TfpWebsocket_close_source_cb;
  read_cb:TfpWebsocket_data_source_cb;
 end;

 TfpWebsocket_session=object
  private
   type
    Trecv_cb=function(session:PfpWebsocket_session;data:Pointer;len:size_t):size_t;
    Tsend_cb=function(session:PfpWebsocket_session;data:Pio_block):size_t;
    Pws_proto_cbs=^Tws_proto_cbs;
    Tws_proto_cbs=object
     recv_cb:Trecv_cb;
     send_cb:Tsend_cb;
    end;
    Tframe_queue=object
     private
      Var
       tail_,head_:Pointer;
       stub_:Pointer;
     public
    end;
   var
    max_messg_size:size_t;
    flags:size_t;
    user_data:Pointer;
    message_cb:TWebsocket_message_callback;
    alloc_chunk_cb:TWebsocket_alloc_chunk_callback;
    protos:Pws_proto_cbs;
    recv:record
     state:SizeUInt;
     FrameSize,
     FramePos,
     MesgSize:qword;
    end;
    send:record
     state:SizeUInt;
     frame_amount:size_t;
     frame_queue:Tframe_queue;
     MesgSize:qword;
     buf:Tio_block;
    end;
 end;

function  fpWebsocket_handshake_server_new(Var option:PfpWebsocket_handshake):Boolean;
function  fpWebsocket_handshake_client_new(Var option:PfpWebsocket_handshake):Boolean;
procedure fpWebsocket_handshake_del(option:PfpWebsocket_handshake);
function  fpWebsocket_handshake_set_header(option:PfpWebsocket_handshake;name:Pointer;namelen:size_t;value:Pointer;valuelen:size_t):Integer;
function  fpWebsocket_handshake_set_secure(option:PfpWebsocket_handshake;sec:Boolean):Boolean;
function  fpWebsocket_handshake_set_data(option:PfpWebsocket_handshake;data:Pointer;len:size_t):size_t;
function  fpWebsocket_handshake_get_data(option:PfpWebsocket_handshake;data:Pointer;len:size_t):size_t;
function  fpWebsocket_handshake_select_version(option:PfpWebsocket_handshake;V:Byte):ShortInt;
function  fpWebsocket_handshake_get_version(option:PfpWebsocket_handshake):ShortInt;
function  fpWebsocket_handshake_get_state(option:PfpWebsocket_handshake):ShortInt;
function  fpWebsocket_handshake_complite(option:PfpWebsocket_handshake):Boolean;
function  fpWebsocket_handshake_get_headers(option:PfpWebsocket_handshake;nva:Pheaders_nv;nvlen:size_t):size_t;

function  fpWebsocket_handshake_mem_send(option:PfpWebsocket_handshake;data:Pio_block):ssize_t;
function  fpWebsocket_handshake_mem_recv(option:PfpWebsocket_handshake;data:Pointer;len:size_t):ssize_t;

procedure fpWebsocket_handshake_set_opt(option:PfpWebsocket_handshake;opt:size_t;value:PAnsiChar;valuelen:size_t);
function  fpWebsocket_handshake_get_opt(option:PfpWebsocket_handshake;opt:size_t):PAnsiChar;

function  fpWebsocket_session_new(Var session:PfpWebsocket_session;flags:size_t):Boolean;
function  fpWebsocket_session_new(Var session:PfpWebsocket_session;option:PfpWebsocket_handshake):Boolean;
procedure fpWebsocket_session_del(session:PfpWebsocket_session);
function  fpWebsocket_session_get_user_data(session:PfpWebsocket_session):Pointer;
procedure fpWebsocket_session_set_user_data(session:PfpWebsocket_session;data:Pointer);
procedure fpWebsocket_session_set_message_cb(session:PfpWebsocket_session;cb:TWebsocket_message_callback);
procedure fpWebsocket_session_set_alloc_chunk_cb(session:PfpWebsocket_session;cb:TWebsocket_alloc_chunk_callback);

function  fpWebsocket_session_mem_recv(session:PfpWebsocket_session;data:Pointer;len:size_t):ssize_t;
function  fpWebsocket_session_mem_send(session:PfpWebsocket_session;data:Pio_block):ssize_t;

function  fpWebsocket_session_get_recv_err(session:PfpWebsocket_session):size_t;
function  fpWebsocket_session_get_send_err(session:PfpWebsocket_session):size_t;

function  fpWebsocket_session_want_write(session:PfpWebsocket_session):Boolean;

function  fpWebsocket_session_buffered_Amount(session:PfpWebsocket_session):SizeUint;

function  fpWebsocket_session_peek_provider(session:PfpWebsocket_session):PfpWebsocket_data_provider;

function  fpWebsocket_session_submit_frame_stream(session:PfpWebsocket_session;data_prd:PfpWebsocket_data_provider;frame_len:size_t;op_code:Byte):Boolean;
function  fpWebsocket_session_submit_frame(session:PfpWebsocket_session;data:PAnsiChar;len:size_t;op_code:Byte):Boolean;
function  fpWebsocket_session_submit_text(session:PfpWebsocket_session;data:PAnsiChar;len:size_t):Boolean; inline;
function  fpWebsocket_session_submit_data(session:PfpWebsocket_session;data:Pointer;len:size_t):Boolean; inline;
function  fpWebsocket_session_submit_ping(session:PfpWebsocket_session;data:Pointer;len:size_t):Boolean; inline;
function  fpWebsocket_session_submit_close(session:PfpWebsocket_session;err_code:Word=0):Boolean;

Procedure io_block_free(P:Pio_block); inline;

function  base64encode(Src:Pointer;SrcLen:size_t;Dst:PAnsiChar;DstLen:size_t):size_t;
function  base64decode(Src:PAnsiChar;SrcLen:size_t;Dst:Pointer;var DstLen:size_t):Integer;

implementation

Const
 ST_ERR=-1;
 ST_SRV_INIT=0;
 ST_SRV_SLCT=1;
 ST_CLN_INIT=2;
 ST_CLN_SLCT=3;
 ST_CLN_CHCK=4;

 DEF_MAX_MESSG_SIZE=1024*1024*1024;

type
 Psubmit_frame=^Tsubmit_frame;
 Tsubmit_frame=object
  next_:Psubmit_frame;
  data_prd:TfpWebsocket_data_provider;
  frame_len:size_t;
  op_code:Byte;
 end;

 Pframe_queue=^Tframe_queue;
 Tframe_queue=TfpWebsocket_session.Tframe_queue;

 PPing_node=^TPing_node;
 TPing_node=record
  queue:Tframe_queue;
  flag:ssize_t;
 end;

 PPing_frame=^TPing_frame;
 TPing_frame=object
  next_:Pointer;
  data:Tio_block;
 end;

 Prfc6455_session=^Trfc6455_session;
 Trfc6455_session=object(TfpWebsocket_session)
  ping_node:PPing_node;
  recv_mask:DWORD;
  send_mask:DWORD;
  recv_frame:array[0..1] of Byte;
 end;

 Phixie_session=^Thixie_session;
 Thixie_session=object(TfpWebsocket_session)
  recv_frame:Byte;
 end;

Procedure io_block_free(P:Pio_block); inline;
begin
 if not Assigned(P) then Exit;
 if Assigned(P^.free) then
 begin
  P^.free(P^.data);
 end;
 P^:=Default(Tio_block);
end;

Procedure submit_frame_free(P:Psubmit_frame); inline;
begin
 if not Assigned(P) then Exit;
 FreeMem(P);
end;

function load_consume(Var addr:Pointer):Pointer; inline;
begin
 ReadDependencyBarrier;
 Result:=addr;
end;

Procedure store_release(Var addr:Pointer;v:Pointer); inline;
begin
 WriteBarrier;
 addr:=v;
end;

function XCHG(Var addr:Pointer;New:Pointer):Pointer; inline;
begin
 Result:=System.InterLockedExchange(addr,New);
end;

function fetch_add(Var addr:SizeUInt;i:SizeUInt):SizeUInt; inline;
begin
 Result:=SizeUInt(System.InterLockedExchangeAdd(Pointer(addr),Pointer(i)));
end;

function fetch_sub(Var addr:SizeUInt;i:SizeUInt):SizeUInt; inline;
begin
 Result:=fetch_add(addr,SizeUInt(-SizeInt(i)));
end;

procedure frame_queue_init(buf:Pframe_queue); inline;
begin
 if not Assigned(buf) then Exit;
 buf^:=Default(Tframe_queue);
 With buf^ do
 begin
  head_:=Psubmit_frame(@stub_);
  tail_:=Psubmit_frame(@stub_);
 end;
 ReadWriteBarrier;
end;

function frame_queue_push(buf:Pframe_queue;Node:Psubmit_frame):Boolean;
Var
 prev:Psubmit_frame;
begin
 if (not Assigned(buf)) or (not Assigned(Node)) then Exit(False);
 With buf^ do
 begin
  store_release(Node^.next_,nil);
  prev:=XCHG(head_,Node);
  store_release(prev^.next_,Node);
 end;
 Result:=True;
end;

function frame_queue_pop(buf:Pframe_queue):Psubmit_frame;
Var
 tail,n,head:Psubmit_frame;
begin
 Result:=nil;
 if not Assigned(buf) then Exit;
 With buf^ do
 begin
  tail:=tail_;
  n:=load_consume(tail^.next_);

  if tail=@stub_ then
  begin
   if n=nil then Exit;
   store_release(tail_,n);
   tail:=n;
   n:=load_consume(n^.next_);
  end;

  if n<>nil then
  begin
   store_release(tail_,n);
   Result:=tail;
   store_release(tail^.next_,nil);
   Exit;
  end;

  head:=head_;
  if tail<>head then Exit;

  stub_:=nil;
  n:=XCHG(head_,@stub_);
  store_release(n^.next_,@stub_);

  n:=load_consume(tail^.next_);

  if n<>nil then
  begin
   store_release(tail_,n);
   Result:=tail;
   store_release(tail^.next_,nil);
   Exit;
  end;
 end;
end;

function frame_queue_peek(buf:Pframe_queue):Psubmit_frame;
Var
 tail,n:Psubmit_frame;
begin
 Result:=nil;
 if not Assigned(buf) then Exit;
 With buf^ do
 begin
  tail:=tail_;
  if not Assigned(tail) then Exit;
  n:=load_consume(tail^.next_);
  if tail=@stub_ then
  begin
   if not Assigned(n) then Exit;
   tail:=n;
  end;
  Result:=tail;
 end;
end;

procedure frame_queue_clear(buf:Pframe_queue);
Var
 Node:Psubmit_frame;
begin
 if not Assigned(buf) then Exit;
 repeat
  Node:=frame_queue_pop(buf);
  submit_frame_free(Node);
 until (Node=nil);
end;

type
 TStrVal=object
  FStr:PChar;
  FLen:SizeUInt;
  function  New(P:Pointer;L:SizeUInt):TStrVal; static;
  function  GetStr:RawByteString; inline;
  Procedure SetStr(Const S:RawByteString); inline;
  Procedure CopyTrim(P:Pointer;L:SizeUint);
  Procedure Free;  inline;
  function  Reserve_z(p:SizeUInt):SizeUInt;
  Procedure Reset; inline;
  Procedure AddStr(Const S:RawByteString);
  Procedure AddPChar(P:PAnsiChar;len:SizeUInt);
  Procedure AddChar(C:AnsiChar); inline;
  Procedure AddCharTrimLeft(C:AnsiChar); inline;
  Procedure TrimRight;
  Procedure TrimLeftUnSafe;
 end;

function TStrVal.New(P:Pointer;L:SizeUInt):TStrVal; inline;
begin
 Result.FStr:=P;
 Result.FLen:=L;
end;

Procedure TStrVal.Free; inline;
begin
 FreeMem(FStr);
 Self:=Default(TStrVal);
end;

function TStrVal.GetStr:RawByteString; inline;
begin
 SetString(Result,FStr,FLen);
end;

Procedure TStrVal.SetStr(Const S:RawByteString); inline;
begin
 FStr:=PChar(S);
 FLen:=Length(S);
end;

Procedure TStrVal.CopyTrim(P:Pointer;L:SizeUint);
begin
 FLen:=0;
 if (P=nil) then Exit;
 while (L>0) and (PAnsiChar(P)[L-1]<=' ') do Dec(L);
 while (L>0) and (PAnsiChar(P)^<=' ') do
 begin
  Inc(P);
  Dec(L);
 end;
 if (L=0) then Exit;
 Reserve_z(L);
 Move(P^,FStr^,L);
end;

function TStrVal.Reserve_z(p:SizeUInt):SizeUInt;
Var
 z,MemLen:SizeUInt;
begin

 if (FStr=nil) then
 begin
  MemLen:=0
 end else
 begin
  MemLen:=MemSize(FStr);
 end;

 Result:=FLen;
 FLen:=FLen+p;
 z:=FLen+1;
 if (MemLen<z) then
 begin
  Case z of
   0..SizeOf(Pointer)*4:
    FStr:=ReAllocMem(FStr,SizeOf(Pointer)*4);
   else
   begin
    p:=Result+(Result div 2);
    if z>p then p:=z;
    FStr:=ReAllocMem(FStr,p);
   end;
  end;
 end;

end;

Procedure TStrVal.Reset; inline;
begin
 FLen:=0;
end;

Procedure TStrVal.AddChar(C:AnsiChar); inline;
Var
 i:SizeUInt;
begin
 i:=Reserve_z(1);
 FStr[i]:=C;
end;

Procedure TStrVal.AddCharTrimLeft(C:AnsiChar); inline;
begin
 if (FLen<>0) or (C>' ') then
 begin
  AddChar(C);
 end;
end;

Procedure TStrVal.AddStr(Const S:RawByteString);
Var
 i:SizeUInt;
begin
 if Length(S)<>0 then
 begin
  i:=Reserve_z(Length(S));
  Move(PAnsiChar(S)^,FStr[i],Length(S));
 end;
end;

Procedure TStrVal.AddPChar(P:PAnsiChar;len:SizeUInt);
Var
 i:SizeUInt;
begin
 if len<>0 then
 begin
  i:=Reserve_z(len);
  Move(P^,FStr[i],len);
 end;
end;

Procedure TStrVal.TrimRight;
Var
 i:SizeUInt;
begin
 if (FStr=nil) then Exit;
 While (FLen<>0) do
 begin
  i:=FLen-1;
  if (FStr[i]>' ') then Exit;
  FLen:=i;
 end;
end;

Procedure TStrVal.TrimLeftUnSafe;
begin
 if (FStr=nil) or (FLen=0) then Exit;
 while (FLen<>0) and (FStr^<=' ') do
 begin
  Dec(FLen);
  Inc(FStr);
 end;
end;

function TryPcharToByte(P:PAnsiChar;Len:SizeUInt;Out Q:Byte):boolean;
Var
 R,T:Byte;
 b:Byte;
begin
 Result:=False;
 if (P=nil) or (Len=0) or (Len>3) then Exit;
 R:=0;
 While (Len<>0) do
 begin
  b:=Byte(P^)-Byte($30);
  if b<=Byte(9) then
  begin
   T:=R*10+b;
   if T<R then Exit;
   R:=T;
  end else
   Exit;
  Inc(P);
  Dec(Len);
 end;
 Q:=R;
 Result:=True;
end;

function  fpWebsocket_handshake_server_new(Var option:PfpWebsocket_handshake):Boolean;
begin
 Result:=true;
 option:=AllocMem(SizeOf(TfpWebsocket_handshake));
 if option=nil then Exit(false);
 option^.state:=ST_SRV_INIT;
 option^.Path:='\';
end;

function  fpWebsocket_handshake_client_new(Var option:PfpWebsocket_handshake):Boolean;
begin
 Result:=true;
 option:=AllocMem(SizeOf(TfpWebsocket_handshake));
 if option=nil then Exit(false);
 option^.state:=ST_CLN_INIT;
end;

procedure fpWebsocket_handshake_del(option:PfpWebsocket_handshake);
begin
 if option=nil then Exit;
 TStrVal(option^.recv.LastName) .Free;
 TStrVal(option^.recv.LastValue).Free;
 Finalize(option^);
 FreeMem(option);
end;

function _on_websec(data:Pointer;len:SizeUInt):SizeInt;
begin
 Result:=-1;
 if (data=nil) then Exit;
 Case len of
  5:Case PDWord(Data)^ or $20202000 of
     $7461703A: //:pat
               Case PByte(Data)[4] or $20 of
                $68:Result:=0; //h
               end;
    end;
  6:Case PDWord(Data)^ or $20202020 of
     $6769726F: //orig
               Case PWord(Data)[2] or $2020 of
                $6E69:Result:=2; //in
               end;
    end;
  7:Case (PQWord(Data)^ and $FFFFFFFFFFFFFF) or $20202020202020 of
     $65646172677075:Result:=1; //upgrade
    end;
  16:Case PQWord(Data)^ or $2020202020202020 of
      $656B636F73626577: //websocke
                        Case PQWord(Data)[1] or $2020202020200020 of
                         $6E696769726F2D74:Result:=8; //t-origin
                        end;
     end;
  17,18,20..22,24:
  begin
   Case PQWord(Data)^ or $2020202000202020 of
    $656B636F73626577, //websocke
    $656B636F53626577: //webSocke
                      Case len of
                       18:Case PQWord(Data)[1] or $2020202200200020 of
                           $697461636F6C2D74: //t-locati
                                             Case PWord(Data)[8] or $2020 of
                                              $6E6F:Result:=9; //on
                                             end;
                           $636F746F72702D74: //t-protoc
                                             Case PWord(Data)[8] or $2020 of
                                              $6C6F:Result:=10; //ol
                                             end;
                          end;
                      end;

    $736265772D636573: //sec-webs
                      Case len of
                       17:Case PQWord(Data)[1] or $2020002020202020 of
                           $656B2D74656B636F: //ocket-ke
                                             Case PByte(Data)[16] or $20 of
                                              $79:Result:=3; //y
                                             end;
                          end;

                       18:Case PQWord(Data)[1] or $2020002020202020 of
                           $656B2D74656B636F: //ocket-ke
                                             Case PWord(Data)[8] or $20 of
                                              $3179:Result:=11; //y1
                                              $3279:Result:=12; //y2
                                             end;
                          end;

                       20:Case PQWord(Data)[1] or $2020002020202020 of
                           $63612D74656B636F: //ocket-ac
                                             Case PDWord(Data)[4] or $20202020 of
                                              $74706563:Result:=7; //cept
                                             end;
                           $726F2D74656B636F: //ocket-or
                                             Case PDWord(Data)[4] or $20202020 of
                                              $6E696769:Result:=13; //igin
                                             end;
                          end;
                       21:Case PQWord(Data)[1] or $2020002020202020 of
                           $65762D74656B636F: //ocket-ve
                                             Case PDWord(Data)[4] or $20202020 of
                                              $6F697372: //rsio
                                                        Case PByte(Data)[20] or $20 of
                                                         $6E:Result:=5; //n
                                                        end;
                                             end;
                          end;
                       22:Case PQWord(Data)[1] or $2020002020202020 of
                           $72702D74656B636F: //ocket-pr
                                             Case PDWord(Data)[4] or $20202020 of
                                              $636F746F: //otoc
                                                        Case PWord(Data)[10] or $2020 of
                                                         $6C6F:Result:=4; //ol
                                                        end;
                                             end;
                           $6F6C2D74656B636F: //ocket-lo
                                             Case PDWord(Data)[4] or $20202020 of
                                              $69746163: //cati
                                                        Case PWord(Data)[10] or $2020 of
                                                         $6E6F:Result:=14; //on
                                                        end;
                                             end;
                          end;
                       24:Case PQWord(Data)[1] or $2020002020202020 of
                           $78652D74656B636F: //ocket-ex
                                             Case PQWord(Data)[2] or $2020202020202020 of
                                              $736E6F69736E6574:Result:=6; //tensions
                                             end;
                       end;
                      end;

   end;
  end;
 end;
end;

function _on_upgrade(data:Pointer;len:SizeUInt):SizeInt;
begin
 Result:=-1;
 if (data=nil) then Exit;
 Case len of
  9:Case PQWord(Data)^ or $2020202020202020 of
     $656B636F73626577: //websocke
                       Case PByte(Data)[8] or $20 of
                        $74:Result:=0; //t
                       end;
  end;
 end;
end;

Function GetStr(data:Pchar;size:size_t):String; inline;
begin
 SetLength(Result,size);
 Move(data^,Result[1],size);
end;

function _parse_versions(option:PfpWebsocket_handshake;data:Pointer;len:SizeUInt):Boolean;
Var
 T:TStrVal;
 i:SizeInt;

 function _on_check(V:TStrVal):Boolean; inline;
 var
  B:Byte;
 begin
  V.TrimLeftUnSafe;
  V.TrimRight;
  Result:=TryPcharToByte(V.FStr,V.FLen,B);
  if Result then
  begin
   Case B of
     7:option^.versions:=option^.versions+[v7];
     8:option^.versions:=option^.versions+[v8];
    13:option^.versions:=option^.versions+[v13];
   end;
  end;
 end;

begin
 T:=TStrVal.New(data,len);
 repeat
  i:=System.IndexByte(T.FStr^,T.FLen,Byte(','));
  if (i=-1) then
  begin
   Result:=_on_check(T);
   Exit;
  end;
  Result:=_on_check(TStrVal.New(T.FStr,i));
  if not Result then Exit;
  T.FStr:=@T.FStr[i+1];
  T.FLen:=T.FLen-i-1;
 until false;
end;

function fpWebsocket_handshake_set_header(option:PfpWebsocket_handshake;name:Pointer;namelen:size_t;value:Pointer;valuelen:size_t):Integer;

 function _set_76v:Boolean; inline;
 begin
  if option^.versions-[vSec,v76]<>[] then
  begin
   option^.state:=ST_ERR;
   Result:=true;
  end else
  begin
   option^.versions:=option^.versions+[v76];
   Result:=false;
  end;
 end;

 function _is_older_srv:Boolean; inline;
 begin
  Result:=option^.versions*[v76]<>[];
 end;

 function _is_new_srv:Boolean; inline;
 begin
  Result:=option^.versions*[v7,v8,v13]<>[];
 end;

 function TryVersion(P:PAnsiChar;Len:SizeUInt;V:Byte):boolean; inline;
 Var
  Q:Byte;
 begin
  Result:=TryPcharToByte(P,Len,Q);
  Result:=Result and (Q=V);
 end;

begin
 if option=nil then Exit(ST_ERR);
 With option^ do
  case state of
    ST_CLN_SLCT:
     case version of
      75:
       case _on_websec(name,namelen) of
        0, //:path (server side)
        2, //Origin (server side)
        3, //Sec-WebSocket-Key (server side)  (new)
        4, //Sec-WebSocket-Protocol (new)
        5, //Sec-WebSocket-Version (new)
        6, //Sec-WebSocket-Extensions (new)
        7, //Sec-WebSocket-Accept (client side) (new)
       11, //sec-websocket-key1 (server side) (old)
       12, //sec-websocket-key2 (server side) (old)
       13, //Sec-WebSocket-Origin   (client 76) (server 7,8)
       14: //Sec-WebSocket-Location (client 76)
          state:=ST_ERR;

        1: //Upgrade
          if _on_upgrade(value,valuelen)<>0 then
           state:=ST_ERR;

        8: //WebSocket-Origin (client side)   (old)
          if (origin<>GetStr(value,valuelen)) then
           state:=ST_ERR;

        9: //WebSocket-Location (client side) (old)
          if Location<>GetStr(value,valuelen) then
           state:=ST_ERR;

       10: //WebSocket-Protocol              (old)
           protocols:=GetStr(value,valuelen);
       end;
      76:
       case _on_websec(name,namelen) of
        0, //:path (server side)
        2, //Origin (server side)
        3, //Sec-WebSocket-Key (server side)  (new)
        5, //Sec-WebSocket-Version (new)
        6, //Sec-WebSocket-Extensions (new)
        7, //Sec-WebSocket-Accept (client side) (new)
        8, //WebSocket-Origin (client side)   (old)
        9, //WebSocket-Location (client side) (old)
       10, //WebSocket-Protocol              (old)
       11, //sec-websocket-key1 (server side) (old)
       12: //sec-websocket-key2 (server side) (old)
          state:=ST_ERR;

        1: //Upgrade
          if _on_upgrade(value,valuelen)<>0 then
           state:=ST_ERR;

        4: //Sec-WebSocket-Protocol (new)
          protocols:=GetStr(value,valuelen);

        13: //Sec-WebSocket-Origin   (client 76) (server 7,8)
          if (origin<>GetStr(value,valuelen)) then
           state:=ST_ERR;

        14: //Sec-WebSocket-Location (client 76)
           if Location<>GetStr(value,valuelen) then
            state:=ST_ERR;
       end;
      7,8,13:
       case _on_websec(name,namelen) of  //new rfc
         0, //:path (server side)
         2, //Origin (server side)
         3, //Sec-WebSocket-Key (server side)  (new)
         8, //WebSocket-Origin (client side)   (old)
         9, //WebSocket-Location (client side) (old)
        10, //WebSocket-Protocol               (old)
        11, //sec-websocket-key1 (server side) (old)
        12, //sec-websocket-key2 (server side) (old)
        13, //Sec-WebSocket-Origin   (client 76) (server 7,8)
        14: //Sec-WebSocket-Location (client 76)
           state:=ST_ERR;

        1: //Upgrade
          if _on_upgrade(value,valuelen)<>0 then
           state:=ST_ERR;

        4: //Sec-WebSocket-Protocol (new)
          if protocols<>'' then
           state:=ST_ERR
          else
          begin
           protocols:=GetStr(value,valuelen);
          end;

        5: //Sec-WebSocket-Version (new)
          if not TryVersion(value,valuelen,version) then
           state:=ST_ERR;

        6: //Sec-WebSocket-Extensions (new)
          if extensions<>'' then
           extensions:=extensions+','+GetStr(value,valuelen)
          else
           extensions:=GetStr(value,valuelen);

        7: //Sec-WebSocket-Accept (client side) (new)
          if key2<>'' then
           state:=ST_ERR
          else
           key2:=GetStr(value,valuelen);

       end;
     end;

   ST_SRV_INIT:
     case _on_websec(name,namelen) of //server side
       7, //Sec-WebSocket-Accept (client side)
       8, //WebSocket-Origin (client side)
       9, //WebSocket-Location (client side)
      14: //Sec-WebSocket-Location (client 76)
         state:=ST_ERR;

       0: //:path (server side)
         if (path<>'') and (path<>'\') then
          state:=ST_ERR
         else
          path:=GetStr(value,valuelen);

       1: //Upgrade
         if _on_upgrade(value,valuelen)<>0 then
          state:=ST_ERR;

       2, //Origin (server side)
      13: //Sec-WebSocket-Origin   (client 76) (server 7,8)
         if (origin<>'') then
          state:=ST_ERR
         else
         begin
          origin:=GetStr(value,valuelen);
         end;

       3: //Sec-WebSocket-Key (server side) (new)
         if (key1<>'') or _is_older_srv then
          state:=ST_ERR
         else
          key1:=GetStr(value,valuelen);

       4: //Sec-WebSocket-Protocol (new)
         if _is_older_srv then
          state:=ST_ERR
         else
         if protocols<>'' then
          protocols:=protocols+','+GetStr(value,valuelen)
         else
          protocols:=GetStr(value,valuelen);

       5: //Sec-WebSocket-Version (new)
         if _is_older_srv then
          state:=ST_ERR
         else
         if not _parse_versions(option,value,valuelen) then
          state:=ST_ERR;

       6: //Sec-WebSocket-Extensions (new)
         if _is_older_srv then
          state:=ST_ERR
         else
         if extensions<>'' then
          extensions:=extensions+','+GetStr(value,valuelen)
         else
          extensions:=GetStr(value,valuelen);

      10: //WebSocket-Protocol (old)
         if _is_new_srv then
          state:=ST_ERR
         else
         begin
          //_set_75v;
          if protocols<>'' then
           protocols:=protocols+','+GetStr(value,valuelen)
          else
           protocols:=GetStr(value,valuelen);
         end;

      11: //sec-websocket-key1 (server side) (old)
         if (key1<>'') or _set_76v then
          state:=ST_ERR
         else
          key1:=GetStr(value,valuelen);
      12: //sec-websocket-key2 (server side) (old)
         if (key2<>'') or _set_76v then
          state:=ST_ERR
         else
          key2:=GetStr(value,valuelen);
     end;
  end;
 Result:=option^.state;
end;

procedure fpWebsocket_handshake_set_opt(option:PfpWebsocket_handshake;opt:size_t;value:PAnsiChar;valuelen:size_t);
var
 URI:TURI;
 q:RawByteString;
begin
 if option=nil then Exit;
 With option^ do
  case state of
   ST_SRV_INIT,ST_SRV_SLCT,ST_CLN_CHCK:
     Case opt of
      WS_OPT_PRT:protocols:=GetStr(value,valuelen);
     end;
   ST_CLN_INIT,ST_CLN_SLCT:
     Case opt of
      WS_OPT_ORG:origin:=GetStr(value,valuelen);
      WS_OPT_URL:
      begin
       URI:=parse_uri(GetStr(value,valuelen));
       Location:=URI.toString();
       Host:=URI.getHost();
       Path:=URI.getPath(True);
       if Path='' then Path:='/';
       q:=URI.getQuery(True);
       if q<>'' then
       begin
        Path:=Path+'?'+q;
       end;
      end;
      WS_OPT_PRT:protocols:=GetStr(value,valuelen);
     end;
  end;
end;

function  fpWebsocket_handshake_get_opt(option:PfpWebsocket_handshake;opt:size_t):PAnsiChar;
begin
 Result:=nil;
 if option=nil then Exit;
 With option^ do
  Case opt of
   WS_OPT_ORG:origin:=PAnsiChar(origin   );
   WS_OPT_URL:Result:=PAnsiChar(Location );
   WS_OPT_PRT:Result:=PAnsiChar(protocols);
  end;
end;

//   2           1        0
//[012345 67|0123 4567|01 234567]
//[012345|01 2345|0123 45|012345]
//   3       2        1      0

function base64encode(Src:Pointer;SrcLen:size_t;Dst:PAnsiChar;DstLen:size_t):size_t;
const
 base64chars:PAnsiChar='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
 n:DWORD;
 c:array[0..3] of AnsiChar;
 pad,cnt:size_t;

begin
 cnt:=SrcLen div 3;
 pad:=SrcLen-cnt*3;

 SrcLen:=cnt shl 2;
 if pad<>0 then SrcLen:=SrcLen+4;
 if (SrcLen>DstLen) then Exit(SrcLen);

 if cnt<>0 then
 begin
  Dec(cnt);
  For cnt:=cnt downto 0 do
  begin
   n:=SwapEndian(PDWORD(Src)^) shr 8;

   c[3]:=base64chars[n and 63];  n:=n shr 6;
   c[2]:=base64chars[n and 63];  n:=n shr 6;
   c[1]:=base64chars[n and 63];  n:=n shr 6;
   c[0]:=base64chars[n];

   PDWORD(Dst)^:=DWORD(c);
   Dst:=Dst+4;
   Src:=Src+3;
  end;
 end;

 case pad of
  1:begin
     n:=PByte(Src)^;

     c[0]:=base64chars[n shr 2];
     c[1]:=base64chars[(n shl 4) and 63];
     c[2]:='=';
     c[3]:='=';

     PDWORD(Dst)^:=DWORD(c);
    end;
  2:begin
     n:=SwapEndian(PWORD(Src)^) shl 2;

     c[3]:='=';
     c[2]:=base64chars[n and 63];  n:=n shr 6;
     c[1]:=base64chars[n and 63];  n:=n shr 6;
     c[0]:=base64chars[n];

     PDWORD(Dst)^:=DWORD(c);
    end;
 end;

 Result:=0;
end;

Const
 WHITESPACE=64;
 EQUALS    =65;
 INVALID   =66;

 base64_d:array[0..255] of Byte=(
    66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
    54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
    29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66
 );

function base64decode(Src:PAnsiChar;SrcLen:size_t;Dst:Pointer;var DstLen:size_t):Integer;
var
 _end:Pointer;
 len:size_t;
 buf:DWORD;
 iter:Byte;
 c:Byte;
begin
 Result:=0;
 iter:=0;
 buf:=0;
 len:=0;
 _end:=Src+SrcLen;
 While (Src<_end) do
 begin
  c:=base64_d[Byte(Src^)]; Inc(Src);
  case c of
   WHITESPACE:Continue;
   INVALID:   Exit(-1);
   EQUALS:
    begin
     Src:=_end;
     Break;
    end;
   else
    begin
     buf:=(buf shl 6) or c;
     Inc(iter);
     if (iter=4) then
     begin
      len:=len+3;
      if (len>DstLen) then Exit(1);
      PByte(Dst)^:=Byte(buf shr 16); Inc(Dst);
      PByte(Dst)^:=Byte(buf shr  8); Inc(Dst);
      PByte(Dst)^:=Byte(buf);        Inc(Dst);
      buf:=0; iter:=0;
     end;
    end;
  end;
 end;
 case iter of
  3:begin
     len:=len+2;
     if (len>DstLen) then Exit(1);
     PByte(Dst)^:=Byte(buf shr 10); Inc(Dst);
     PByte(Dst)^:=Byte(buf shr  2);
    end;
  2:begin
     len:=len+1;
     if (len>DstLen) then Exit(1);
     PByte(Dst)^:=Byte(buf shr 4);
    end;
 end;
 DstLen:=len;
end;

function _get_webs13_key(const Key:RawByteString):RawByteString;
var
 Context:TSHA1Context;
 Digest:TSHA1Digest;
const
 webs13key='258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
begin
 SHA1Init  (Context);
 SHA1Update(Context,PAnsiChar(key)^      ,length(key));
 SHA1Update(Context,PAnsiChar(webs13key)^,length(webs13key));
 SHA1Final (Context,Digest);

 SetLength(Result,28);
 base64encode(@Digest,SizeOf(Digest),PAnsiChar(Result),28);
end;

function _gen_webs13_key:RawByteString;
Var
 Context:TMTRandomContext;
 key:array[0..3] of DWORD;
begin
 Context:=Default(TMTRandomContext);
 RandomInit(Context);
 key[0]:=Random(Context,high(DWORD)-2)+1;
 key[1]:=Random(Context,high(DWORD)-2)+1;
 key[2]:=Random(Context,high(DWORD)-2)+1;
 key[3]:=Random(Context,high(DWORD)-2)+1;

 SetLength(Result,24);
 base64encode(@key,SizeOf(key),PAnsiChar(Result),24);
end;

function _gen_webs76_key(var Context:TMTRandomContext):RawByteString;
Var
 spaces,chars,i,p:Byte;
 Ch:AnsiChar;
 number:DWORD;
 product:QWORD;
begin
 spaces:=Random(Context,12)+1;
 number:=Random(Context,high(DWORD)-2)+1;
 product:=number*spaces;
 Result:=IntToStr(product);

 chars:=Random(Context,12)+1;
 For i:=1 to chars do
 begin
  p:=Random(Context,$54);
  Case p of
   00..$0E:Ch:=AnsiChar(p+$21);
   $F..$53:Ch:=AnsiChar(p+$2B);
  end;
  p:=Random(Context,Length(Result))+1;
  Insert(Ch,Result,p);
 end;

 if Length(Result)>1 then
 For i:=1 to spaces do
 begin
  p:=Random(Context,Length(Result)-2)+2;
  Insert(' ',Result,p);
 end;
end;

procedure _gen_webs76_keys(var key1,key2,key3:RawByteString);
Var
 Context:TMTRandomContext;
 key:array[0..1] of DWORD;
begin
 Context:=Default(TMTRandomContext);
 RandomInit(Context);
 key1:=_gen_webs76_key(Context);
 key2:=_gen_webs76_key(Context);
 key[0]:=Random(Context,high(DWORD)-2)+1;
 key[1]:=Random(Context,high(DWORD)-2)+1;
 SetString(key3,@key,SizeOf(key));
end;

function _gen_mask:DWORD;
Var
 Context:TMTRandomContext;
begin
 Context:=Default(TMTRandomContext);
 RandomInit(Context);
 Result:=Random(Context,high(DWORD)-2)+1;
end;

function _get_webs_location(const origin,path:RawByteString;sec:Boolean):RawByteString;
begin
 Result:='';
 if Length(origin)=0 then Exit;
 Result:=parse_uri(origin).getHost();
 if sec then
 begin
  Result:='wss://'+Result+path;
 end else
 begin
  Result:='ws://'+Result+path;
 end;
end;

function _get_sec_num(P:PAnsiChar;Len:SizeUInt;Var DK:DWORD):Boolean;
Var
 R,S:QWord;
 b:Byte;
begin
 Result:=false;
 if (P=nil) or (Len=0) then Exit;
 R:=0;
 S:=0;
 While (Len<>0) do
 begin
  b:=Byte(P^)-Byte($30);
  if b<=Byte(9) then
  begin
   R:=R*10+b;
  end else
  if b=$F0 then Inc(s); //P^=' '
  Inc(P);
  Dec(Len);
 end;
 if (S=0) then Exit;
 if (R mod S)<>0 then Exit;
 R:=R div S;
 DK:=NtoBE(DWORD(R));
 Result:=True;
end;

function _get_webs76_key(const Key1,Key2,Key3:RawByteString):RawByteString;
var
 Context:TMDContext;
 DK:DWORD;
begin
 Result:='';
 MDInit(Context,MD_VERSION_5);
 DK:=0;
 if not _get_sec_num(PAnsiChar(Key1),Length(Key1),DK) then Exit;
 MDUpdate(Context,DK,SizeOf(DK));
 if not _get_sec_num(PAnsiChar(Key2),Length(Key2),DK) then Exit;
 MDUpdate(Context,DK,SizeOf(DK));
 MDUpdate(Context,PAnsiChar(Key3)^,Length(Key3));
 SetLength(Result,SizeOf(TMDDigest));
 MDFinal(Context,PMDDigest(PAnsiChar(Result))^);
end;

function fpWebsocket_handshake_set_secure(option:PfpWebsocket_handshake;sec:Boolean):Boolean;
begin
 Result:=false;
 if (option<>nil)  then
 begin
  Case sec of
   True :option^.versions:=option^.versions+[vSec];
   False:option^.versions:=option^.versions-[vSec];
  end;
  Result:=true;
 end;
end;

function fpWebsocket_handshake_set_data(option:PfpWebsocket_handshake;data:Pointer;len:size_t):size_t;
var
 L:SizeUint;
begin
 Result:=0;

 if (option<>nil) then
  Case option^.state of
   ST_SRV_INIT:if (v76 in option^.versions) then
               begin
                if (data<>nil) and (len<>0) then
                begin
                 L:=option^.recv.LastValue.FLen;
                 if L+len>=8 then len:=8-L;
                 TStrVal(option^.recv.LastValue).AddPChar(PAnsiChar(data),len);
                 Result:=len;
                end else
                begin
                 Result:=8-option^.recv.LastValue.FLen;
                end;
               end;
   ST_CLN_SLCT:if (option^.version=76) then
               begin
                if (data<>nil) and (len<>0) then
                begin
                 L:=option^.recv.LastValue.FLen;
                 if L+len>=16 then len:=16-L;
                 TStrVal(option^.recv.LastValue).AddPChar(PAnsiChar(data),len);
                 Result:=len;
                end else
                begin
                 Result:=16-option^.recv.LastValue.FLen;
                end;
               end;
  end;
end;

function fpWebsocket_handshake_get_data(option:PfpWebsocket_handshake;data:Pointer;len:size_t):size_t;
begin
 Result:=0;

 if (option<>nil) then
  Case option^.state of
   ST_SRV_SLCT:if (option^.version=76) then
               begin
                if (data<>nil) and (len<>0) then
                begin
                 if (len<16) or (Length(option^.key3)<>16) then Exit;
                 Move(PAnsiChar(option^.key3)^,data^,16);
                 Result:=16;
                end else
                begin
                 Result:=16;
                end;
               end;
   ST_CLN_SLCT:if (option^.version=76) then
               begin
                if (data<>nil) and (len<>0) then
                begin
                 if (len<8) or (Length(option^.key3)<>8) then Exit;
                 Move(PAnsiChar(option^.key3)^,data^,8);
                 Result:=8;
                end else
                begin
                 Result:=8;
                end;
               end;
  end;
end;

function fpWebsocket_handshake_get_version(option:PfpWebsocket_handshake):ShortInt;
begin
 Result:=ST_ERR;
 if option=nil then Exit;
 if option^.state<>ST_ERR then
  Result:=option^.version;
end;

function fpWebsocket_handshake_get_state(option:PfpWebsocket_handshake):ShortInt;
begin
 Result:=ST_ERR;
 if option=nil then Exit;
 Result:=option^.state;
end;

function fpWebsocket_handshake_complite(option:PfpWebsocket_handshake):Boolean;
begin
 Result:=false;
 if option=nil then Exit;
 case option^.state of
  ST_SRV_SLCT,
  ST_CLN_CHCK:Result:=true;
 end;
end;

function fpWebsocket_handshake_select_version(option:PfpWebsocket_handshake;V:Byte):ShortInt;
begin
 Result:=ST_ERR;
 if option=nil then Exit;
 With option^ do
  case state of
   ST_CLN_SLCT:
    case version of
     75:
      begin
       state:=ST_CLN_CHCK;
       Result:=version;
      end;
     76:
      begin
       if TStrVal(recv.LastValue).GetStr<>_get_webs76_key(Key1,Key2,Key3) then
       begin
        state:=ST_ERR;
        Exit;
       end;
       state:=ST_CLN_CHCK;
       Result:=version;
      end;
     7,8,13:
      begin
       if key2<>_get_webs13_key(key1) then
       begin
        state:=ST_ERR;
        Exit;
       end;
       state:=ST_CLN_CHCK;
       Result:=version;
      end;
    end;

   ST_CLN_INIT:
      begin
       case V of
        0:V:=13;
        75,76,7..8,13:;
       end;

       Case V of
        75:begin
            version:=V;
            state:=ST_CLN_SLCT;
            Result:=V;
           end;
        76:begin
            _gen_webs76_keys(key1,key2,key3);
            version:=V;
            state:=ST_CLN_SLCT;
            Result:=V;
           end;
        7..8,
        13:begin
            key1:=_gen_webs13_key;
            key2:='';
            version:=V;
            state:=ST_CLN_SLCT;
            Result:=V;
           end;
       end;

      end;
   ST_SRV_INIT:
    begin
      if V=0 then
      begin
       if (v13 in versions) then
        V:=13
       else
       if (v8 in versions) then
        V:=8
       else
       if (v7 in versions) then
        V:=7
       else
       if (v76 in versions) then
        V:=76
       else
        V:=75;
      end;

      Case V of
       7..8,
       13:begin
           Case V of
             7:if not (v7  in versions) then Exit;
             8:if not (v8  in versions) then Exit;
            13:if not (v13 in versions) then Exit;
           end;
           if (key1='') then
           begin
            state:=ST_ERR;
            Exit;
           end;
           key2:=_get_webs13_key(key1);
           version:=V;
           state:=ST_SRV_SLCT;
           Result:=V;
          end;
       75:if (versions-[vSec]=[]) then
          begin
           if (origin='') or (path='') then
           begin
            state:=ST_ERR;
            Exit;
           end;
           Location:=_get_webs_location(origin,path,vSec in versions);
           version:=V;
           state:=ST_SRV_SLCT;
           Result:=V;
          end;
       76:if (v76 in versions) then
          begin
           if (key1='') or (key2='') or (recv.LastValue.FLen=0) or (origin='') or (path='') then
           begin
            state:=ST_ERR;
            Exit;
           end;
           Location:=_get_webs_location(origin,path,vSec in versions);
           key3:=_get_webs76_key(key1,key2,TStrVal(recv.LastValue).GetStr);
           if (key3='') then
           begin
            state:=ST_ERR;
            Exit;
           end;
           version:=V;
           state:=ST_SRV_SLCT;
           Result:=V;
          end;
      end;

     end;

  end;
end;

const
 NV_FLAG_NO_COPY_NAME  = $02;
 NV_FLAG_NO_COPY_VALUE = $04;
 NV_FLAG_NO_COPY       = NV_FLAG_NO_COPY_NAME or NV_FLAG_NO_COPY_VALUE;

function make_nn(const name,value:RawByteString):Theaders_nv; inline;
begin
 Result.name    :=PAnsiChar(name);
 Result.value   :=PAnsiChar(value);
 Result.namelen :=Length(name);
 Result.valuelen:=Length(value);
 Result.flags   :=NV_FLAG_NO_COPY;
end;

function make_nv(const name,value:RawByteString):Theaders_nv; inline;
begin
 Result.name    :=PAnsiChar(name);
 Result.value   :=PAnsiChar(value);
 Result.namelen :=Length(name);
 Result.valuelen:=Length(value);
 Result.flags   :=NV_FLAG_NO_COPY_NAME;
end;

const
 M_GET                   ='GET';
 NGHTTP2_authority       =':authority';
 NGHTTP2_method          =':method';
 NGHTTP2_path            =':path';
 NGHTTP2_status          =':status';
 HTTP_101W               ='101 Web Socket Protocol Handshake';
 HTTP_101S               ='101 Switching Protocols';
 HTTP_Upgrade            ='Upgrade';
 HTTP_websocket          ='WebSocket';
 HTTP_connection         ='Connection';
 HTTP_SWebSocket_Key     ='Sec-WebSocket-Key';
 HTTP_SWebSocket_Accept  ='Sec-WebSocket-Accept';
 HTTP_SWebSocket_Protocol='Sec-WebSocket-Protocol';
 HTTP_SWebSocket_Version ='Sec-WebSocket-Version';
 HTTP_SWebSocket_Origin  ='Sec-WebSocket-Origin';
 HTTP_SWebSocket_Location='Sec-WebSocket-Location';

 HTTP_WebSocket_Origin   ='WebSocket-Origin';
 HTTP_WebSocket_Location ='WebSocket-Location';
 HTTP_WebSocket_Protocol ='WebSocket-Protocol';

 HTTP_Origin             ='Origin';

 HTTP_Sec_WebSocket_Key1 ='Sec-WebSocket-Key1';
 HTTP_Sec_WebSocket_Key2 ='Sec-WebSocket-Key2';

 HTTP_7 ='7';
 HTTP_8 ='8';
 HTTP_13='13';

function  fpWebsocket_handshake_get_headers(option:PfpWebsocket_handshake;nva:Pheaders_nv;nvlen:size_t):size_t;
var
 i:size_t;
begin
 Result:=0;
 if (option=nil) then Exit;
 Case option^.state of
  ST_CLN_SLCT:
   Case option^.version of

    75:begin //client
        Result:=6;
        if Length(option^.protocols)<>0 then Inc(Result);
        if (nva=nil) or (nvlen<Result) then Exit;

        nva[0]:=make_nn(NGHTTP2_method   ,M_GET);
        nva[1]:=make_nv(NGHTTP2_path     ,option^.Path);
        nva[2]:=make_nv(NGHTTP2_authority,option^.Host);

        nva[3]:=make_nn(HTTP_Upgrade     ,HTTP_websocket);
        nva[4]:=make_nn(HTTP_connection  ,HTTP_Upgrade);

        nva[5]:=make_nv(HTTP_Origin,option^.origin);

        if Length(option^.protocols)<>0 then
        begin
         nva[6]:=make_nv(HTTP_WebSocket_Protocol,option^.protocols);
        end;
       end;

    76:begin //client
        Result:=8;
        if Length(option^.protocols)<>0 then Inc(Result);
        if (nva=nil) or (nvlen<Result) then Exit;

        nva[0]:=make_nn(NGHTTP2_method   ,M_GET);
        nva[1]:=make_nv(NGHTTP2_path     ,option^.Path);
        nva[2]:=make_nv(NGHTTP2_authority,option^.Host);

        nva[3]:=make_nn(HTTP_Upgrade     ,HTTP_websocket);
        nva[4]:=make_nn(HTTP_connection  ,HTTP_Upgrade);

        nva[5]:=make_nv(HTTP_Origin,option^.origin);

        nva[6]:=make_nv(HTTP_Sec_WebSocket_Key1,option^.key1);
        nva[7]:=make_nv(HTTP_Sec_WebSocket_Key2,option^.key2);

        if Length(option^.protocols)<>0 then
        begin
         nva[8]:=make_nv(HTTP_WebSocket_Protocol,option^.protocols);
        end;

       end;

    7,8,13:
     begin //client
       Result:=8;
       if Length(option^.protocols)<>0 then Inc(Result);

       if (nva=nil) or (nvlen<Result) then Exit;

       nva[0]:=make_nn(NGHTTP2_method   ,M_GET);
       nva[1]:=make_nv(NGHTTP2_path     ,option^.Path);
       nva[2]:=make_nv(NGHTTP2_authority,option^.Host);

       nva[3]:=make_nn(HTTP_Upgrade    ,HTTP_websocket);
       nva[4]:=make_nn(HTTP_connection ,HTTP_Upgrade);

       nva[5]:=make_nv(HTTP_SWebSocket_Key,option^.key1);

       Case option^.version of
          7,
          8:nva[6]:=make_nv(HTTP_SWebSocket_Origin,option^.origin);
         13:nva[6]:=make_nv(HTTP_Origin           ,option^.origin);
       end;

       i:=7;
       if Length(option^.protocols)<>0 then
       begin
        nva[i]:=make_nv(HTTP_SWebSocket_Protocol,option^.protocols);
        Inc(i);
       end;

       Case option^.version of
          7:nva[i]:=make_nn(HTTP_SWebSocket_Version,HTTP_7);
          8:nva[i]:=make_nn(HTTP_SWebSocket_Version,HTTP_8);
         13:nva[i]:=make_nn(HTTP_SWebSocket_Version,HTTP_13);
       end;

     end;
   end;

  ST_SRV_SLCT:
   Case option^.version of
    7,8,13:
     begin //server
      Result:=4;
      if Length(option^.protocols)<>0 then Inc(Result);

      Case option^.version of
        7:if option^.versions-[ v7]<>[] then Inc(Result);
        8:if option^.versions-[ v8]<>[] then Inc(Result);
       13:if option^.versions-[v13]<>[] then Inc(Result);
      end;

      if (nva=nil) or (nvlen<Result) then Exit;
      nva[0]:=make_nn(NGHTTP2_status  ,HTTP_101S);
      nva[1]:=make_nn(HTTP_Upgrade    ,HTTP_websocket);
      nva[2]:=make_nn(HTTP_connection ,HTTP_Upgrade);

      nva[3]:=make_nv(HTTP_SWebSocket_Accept,option^.key2);

      i:=4;
      if Length(option^.protocols)<>0 then
      begin
       nva[4]:=make_nv(HTTP_SWebSocket_Protocol,option^.protocols);
       Inc(i);
      end;

      Case option^.version of
        7:if option^.versions-[v7]<>[] then
           nva[i]:=make_nn(HTTP_SWebSocket_Version,HTTP_7);
        8:if option^.versions-[v8]<>[] then
           nva[i]:=make_nn(HTTP_SWebSocket_Version,HTTP_8);
       13:if option^.versions-[v13]<>[] then
           nva[i]:=make_nn(HTTP_SWebSocket_Version,HTTP_13);
      end;

     end;

   75:begin //server
       Result:=5;
       if Length(option^.protocols)<>0 then Inc(Result);
       if (nva=nil) or (nvlen<Result) then Exit;
       nva[0]:=make_nn(NGHTTP2_status  ,HTTP_101W);
       nva[1]:=make_nn(HTTP_Upgrade    ,HTTP_websocket);
       nva[2]:=make_nn(HTTP_connection ,HTTP_Upgrade);

       nva[3]:=make_nv(HTTP_WebSocket_Origin,option^.origin);

       nva[4]:=make_nv(HTTP_WebSocket_Location,option^.Location);

       if Length(option^.protocols)<>0 then
       begin
        nva[5]:=make_nv(HTTP_WebSocket_Protocol,option^.protocols);
       end;
      end;
   76:begin //server
       Result:=5;
       if Length(option^.protocols)<>0 then Inc(Result);
       if (nva=nil) or (nvlen<Result) then Exit;
       nva[0]:=make_nn(NGHTTP2_status  ,HTTP_101W);
       nva[1]:=make_nn(HTTP_Upgrade    ,HTTP_websocket);
       nva[2]:=make_nn(HTTP_connection ,HTTP_Upgrade);

       nva[3]:=make_nv(HTTP_SWebSocket_Origin,option^.origin);

       nva[4]:=make_nv(HTTP_SWebSocket_Location,option^.Location);

       if Length(option^.protocols)<>0 then
       begin
        nva[5]:=make_nv(HTTP_SWebSocket_Protocol,option^.protocols);
       end;
      end;
   end;

 end;

end;

Procedure _nvp_mem_reserve(Data:PPointer;size:Ptruint); inline;
begin
 if Data^=nil then
 begin
  Data^:=GetMem(size);
 end else
 if size>MemSize(Data^) then
 begin
  Data^:=ReAllocMem(Data^,size);
 end;
end;

procedure _nvp_add(Data:PPointer;var Result:ssize_t;P:PByte;L:ssize_t);
Var
 i:ssize_t;
begin
 if (P=nil) or (L<=0) then Exit;
 if Data=nil then
 begin
  Result:=Result+L;
  Exit;
 end;
 i:=Result+L;
 _nvp_mem_reserve(Data,i);
 if (Data^=nil) then Exit;
 Move(P^,PByte(Data^)[Result],L);
 Result:=i;
end;

Const
 http1_A         ='HTTP/1.1 ';
 http1_NL        =#13#10;
 http1_VR        =': ';
 http1_GET_SP    ='GET ';
 http1_VER_SP_NL =' HTTP/1.1'#13#10;
 http1_hst_SP    ='Host: ';

function fpWebsocket_handshake_mem_send(option:PfpWebsocket_handshake;data:Pio_block):ssize_t;

 procedure add(P:PChar;L:ssize_t); inline;
 begin
  _nvp_add(@data^.data,Result,PByte(P),L);
 end;

 procedure add(P:PByte;L:ssize_t); inline;
 begin
  _nvp_add(@data^.data,Result,P,L);
 end;

Var
 i:ssize_t;
 nvlen:size_t;
 nva:array[0..8] of Theaders_nv;

begin
 Result:=0;
 if (option=nil) then Exit;
 data^:=Default(Tio_block);
 case option^.state of
  ST_ERR:Result:=-1;
  ST_SRV_INIT:begin
               Case option^.recv.state of
                0://headers
                begin
                 nvlen:=fpWebsocket_handshake_get_headers(option,@nva,Length(nva));
                 if nvlen=0 then Exit;
                 add(http1_A,Length(http1_A));
                 add(nva[0].value   ,nva[0].valuelen);
                 add(http1_NL     ,Length(http1_NL));
                 if nvlen>1 then
                 For i:=1 to nvlen-1 do
                  if (nva[i].name<>nil) and (nva[i].namelen<>0) then
                  begin
                   add(nva[i].name  ,nva[i].namelen);
                   add(http1_VR   ,Length(http1_VR));
                   add(nva[i].value ,nva[i].valuelen);
                   add(http1_NL   ,Length(http1_NL));
                  end;
                 add(http1_NL     ,Length(http1_NL));
                 data^.len:=Result;
                 option^.recv.state:=1;
                end;
                1://data
                begin
                 Result:=fpWebsocket_handshake_get_data(option,nil,0);
                 if Result<>0 then
                 begin
                  _nvp_mem_reserve(@data^.data,Result);
                  Result:=fpWebsocket_handshake_get_data(option,data^.data,Result);
                  data^.len:=Result;
                 end;
                 option^.recv.state:=2;
                end;
               end;
              end;
  ST_CLN_SLCT:begin
               Case option^.recv.state of
                0://headers
                begin
                 nvlen:=fpWebsocket_handshake_get_headers(option,@nva,Length(nva));
                 if nvlen=0 then Exit;

                 add(http1_GET_SP,Length(http1_GET_SP));
                 add(nva[1].value ,nva[1].valuelen);
                 add(http1_VER_SP_NL,Length(http1_VER_SP_NL));

                 if (nva[2].name<>nil) and (nva[2].namelen<>0) then
                 begin
                  add(http1_hst_SP,Length(http1_hst_SP));
                  add(nva[2].value ,nva[2].valuelen);
                  add(http1_NL,Length(http1_NL));
                 end;

                 if nvlen>3 then
                 For i:=3 to nvlen-1 do
                  if (nva[i].name<>nil) and (nva[i].namelen<>0) then
                  begin
                   add(nva[i].name  ,nva[i].namelen);
                   add(http1_VR   ,Length(http1_VR));
                   add(nva[i].value ,nva[i].valuelen);
                   add(http1_NL   ,Length(http1_NL));
                  end;
                 add(http1_NL     ,Length(http1_NL));
                 data^.len:=Result;
                 option^.recv.state:=1;
                end;
                1://data
                begin
                 Result:=fpWebsocket_handshake_get_data(option,nil,0);
                 if Result<>0 then
                 begin
                  _nvp_mem_reserve(@data^.data,Result);
                  Result:=fpWebsocket_handshake_get_data(option,data^.data,Result);
                  data^.len:=Result;
                 end;
                 option^.recv.state:=2;
                end;
               end;
              end;
 end;
end;

function _parse_char(option:PfpWebsocket_handshake;Ch:AnsiChar):ShortInt;

 procedure setstate(s:Byte); inline;
 begin
  option^.recv.state:=s;
 end;

begin
 Result:=0;
 With option^.recv do
  Case state of
   2:begin
      TStrVal(LastValue).Reset;
      TStrVal(LastValue).AddChar(Ch);
      setstate(3);
      Result:=1; //begin
     end;
   3:Case Ch of
      #10:begin
           setstate(8);
           Result:=2; //method/version
          end;
      #13:begin
           setstate(7);
           Result:=2; //method/version
          end;
      ' ':begin
           setstate(4);
           Result:=2; //method/version
          end;
      else
          TStrVal(LastValue).AddChar(Ch);
     end;
   4:Case Ch of
      #10:Result:=-1;
      #13:Result:=-1;
      ' ':Result:=-1;
      else
       begin
        setstate(5);
        TStrVal(LastValue).AddChar(Ch);
       end;
     end;
   5:Case Ch of
      #10:Result:=3;  //version 0.9/not message #10
      #13:Result:=4;  //version 0.9/not message #13
      ' ':begin
           setstate(6);
           Result:=5;  //path/status
          end;
      else
          TStrVal(LastValue).AddChar(Ch);
     end;
   6:Case Ch of
      #10:begin
           setstate(8);
           Result:=6;  //version/message
          end;
      #13:begin
           setstate(7);
           Result:=6;  //version/message
         end;
      else
          TStrVal(LastValue).AddCharTrimLeft(Ch);
     end;
   7:Case Ch of
      #10:setstate(8);
      #13:begin
           setstate(11+2);
           Result:=8;  //field value
          end;
      else
          begin
           setstate(9);
           TStrVal(LastName).AddChar(Ch);
          end;
     end;
   8:Case Ch of
      #10:begin
           setstate(14);
           Result:=8;  //field value
          end;
      #13:begin
           setstate(13);
           Result:=8;  //field value
          end;
      else
          begin
           setstate(9);
           TStrVal(LastName).AddChar(Ch);
          end;
     end;
   9:Case Ch of
      #10:setstate(8);
      #13:setstate(7);
      ':':begin
           setstate(10);
           Result:=7;  //field name
          end;
      else
          TStrVal(LastName).AddChar(Ch);
     end;
   10:Case Ch of
      #10:setstate(12);
      #13:setstate(11);
      else
          TStrVal(LastValue).AddCharTrimLeft(Ch);
     end;
   11:Case Ch of
      #10:setstate(12);
      #13:begin
           setstate(13);
           Result:=8;  //field value
          end;
      ' ':setstate(10);
      else
          begin
           setstate(9);
           Result:=9;  //field value and add
          end;
     end;
  12:Case Ch of
      #10:begin
           setstate(14);
           Result:=8;  //field value
          end;
      #13:begin
           setstate(13);
           Result:=8;  //field value
          end;
      ' ':setstate(10);
      else
          begin
           setstate(9);
           Result:=9;  //field value and add
          end;
     end;
  13:Case Ch of
      #10:setstate(14);
      else
          Result:=-1;
     end;

  end;
end;


function fpWebsocket_handshake_mem_recv(option:PfpWebsocket_handshake;data:Pointer;len:size_t):ssize_t;
var
 i:size_t;

 procedure setstate(s:Byte); inline;
 begin
  option^.recv.state:=s;
 end;

 function _on_version_cb_val:Boolean; inline;
 begin
  With option^.recv do
  begin
   TStrVal(LastValue).TrimRight;
   Result:=(LastValue.FLen=8) and ((PQWord(LastValue.FStr)^ or $20202020)=$312E312F70747468);
   TStrVal(LastValue).Reset;
  end;
 end;

 function _on_status_cb_val:Boolean; inline;
 begin
  With option^.recv do
  begin
   Result:=(LastValue.FLen=3) and
           ((PDWORD(LastValue.FStr)^ and $FFFFFF)=$313031);
   TStrVal(LastValue).Reset;
  end;
 end;

 function _on_method_cb_val:Boolean; inline;
 begin
  With option^.recv do
  begin
   Result:=(LastValue.FLen=3) and
           ((PDWORD(LastValue.FStr)^ and $FFFFFF)=$746567);
   TStrVal(LastValue).Reset;
  end;
 end;

 function _on_field_cb_val:Boolean;
 begin
  Result:=true;
  With option^.recv do
  begin
   TStrVal(LastValue).TrimRight;
   if (LastName .FLen=0) or
      (LastValue.FLen=0) then
   begin
    Exit;
   end;
   Result:=fpWebsocket_handshake_set_header(option,LastName.FStr,LastName.FLen,
                                                   LastValue.FStr,LastValue.FLen)<>ST_ERR;
   TStrVal(LastName ).Reset;
   TStrVal(LastValue).Reset;
  end;
 end;

 function _on_path_cb_val:Boolean; inline;
 begin
  With option^.recv do
  begin
   TStrVal(LastValue).TrimRight;
   Result:=TStrVal(LastValue).GetStr=option^.Path;
   TStrVal(LastValue).Reset;
  end;
 end;

begin
 Result:=0;
 if (option=nil) or (data=nil) or (len=0) then Exit;
 case option^.state of
  ST_ERR:Result:=-1;
  ST_CLN_SLCT:begin
               if option^.recv.state=1 then
               begin
                Result:=fpWebsocket_handshake_set_data(option,data,len);
                if fpWebsocket_handshake_set_data(option,nil,0)=0 then
                begin
                 fpWebsocket_handshake_select_version(option,0);
                end;
               end else
               if option^.recv.state<2 then Exit;

               i:=len;
               While (i<>0) do
               begin
                With option^.recv do
                Case _parse_char(option,PChar(data)^) of
                 -1:
                 begin
                  option^.state:=ST_ERR;
                  Exit(len-i);
                 end;
                 1:;//begin
                 2:if not _on_version_cb_val then //version
                   begin
                    option^.state:=ST_ERR;
                    Exit(len-i);
                   end;
                 3:begin //status
                    if not _on_status_cb_val then
                    begin
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                    setstate(6); //not message #10
                   end;
                 4:begin //status
                    if not _on_status_cb_val then
                    begin
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                    setstate(5); //not message #13
                   end;
                 5:if not _on_status_cb_val then //status
                   begin
                    option^.state:=ST_ERR;
                    Exit(len-i);
                   end;
                 6:TStrVal(LastValue).Reset;    //message ignore
                 7:TStrVal(LastName).TrimRight; //field name
                 8:if not _on_field_cb_val then //field value
                   begin
                    option^.state:=ST_ERR;
                    Exit(len-i);
                   end;
                 9:begin;               //field value and add
                    if not _on_field_cb_val then
                    begin
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                    TStrVal(LastName).AddChar(PChar(data)^);
                   end;
                end;

                if option^.recv.state=14 then
                begin
                 Dec(i);
                 Result:=len-i;

                 TStrVal(option^.recv.LastName) .Free;
                 TStrVal(option^.recv.LastValue).Free;

                 if fpWebsocket_handshake_set_data(option,nil,0)<>0 then
                 begin
                  option^.recv.state:=1;
                 end else
                 begin
                  fpWebsocket_handshake_select_version(option,0);
                 end;

                 Exit;
                end;

                Dec(i);
                Inc(data);
               end;
               Result:=len-i;
              end;
  ST_SRV_INIT:begin
               if option^.recv.state=1 then
               begin
                Result:=fpWebsocket_handshake_set_data(option,data,len);
                if fpWebsocket_handshake_set_data(option,nil,0)=0 then
                begin
                 fpWebsocket_handshake_select_version(option,0);
                end;
               end else
               if option^.recv.state<2 then Exit;

               i:=len;
               While (i<>0) do
               begin
                 With option^.recv do
                 Case _parse_char(option,PChar(data)^) of
                  -1:
                  begin
                   option^.state:=ST_ERR;
                   Exit(len-i);
                  end;
                  1:;  //begin
                  2:if not _on_method_cb_val then //method
                    begin
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                  3:begin //version 0.9 #10
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                  4:begin //version 0.9 #13
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                  5:if not _on_path_cb_val then  //path
                    begin
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                  6:if not _on_version_cb_val then  //version
                    begin
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                  7:TStrVal(LastName).TrimRight;    //field name
                  8:if not _on_field_cb_val then    //field value
                    begin
                     option^.state:=ST_ERR;
                     Exit(len-i);
                    end;
                  9:begin;               //field value and add
                     if not _on_field_cb_val then
                     begin
                      option^.state:=ST_ERR;
                      Exit(len-i);
                     end;
                     TStrVal(LastName).AddChar(PChar(data)^);
                    end;
                 end;

                 if option^.recv.state=14 then
                 begin
                  Dec(i);
                  Result:=len-i;

                  TStrVal(option^.recv.LastName ).Free;
                  TStrVal(option^.recv.LastValue).Free;

                  if fpWebsocket_handshake_set_data(option,nil,0)<>0 then
                  begin
                   option^.recv.state:=1;
                  end else
                  begin
                   fpWebsocket_handshake_select_version(option,0);
                  end;

                  Exit;
                 end;

                Dec(i);
                Inc(data);
               end;
               Result:=len-i;
              end;
 end;


end;


procedure _masked(Src:PByte;pos,len:size_t;mask:dword);
var
 i:size_t;
begin
 i:=0;

 i:=pos and 3;
 if (i<>0) then
 begin
  repeat
   Src^:=Src^ xor PByte(@mask)[i];
   Inc(i);
   Inc(Src);
   Dec(len);
   if (len=0) then Exit;
  until (i=4);
  pos:=pos and (not 3);
 end;

 i:=len shr 2;

 While (i<>0) do
 begin
  PDWORD(Src)^:=PDWORD(Src)^ xor mask;
  Inc(Src,4);
  Dec(i);
 end;

 len:=len and 3;
 if (len<>0) then
 begin
  i:=0;
  repeat
   Src^:=Src^ xor PByte(@mask)[i];
   Inc(i);
   Inc(Src);
  until (i=len);
 end;
end;

function _new_chunk(session:PfpWebsocket_session;data:Pointer;len:size_t):Tio_block; inline;
begin
 Result:=session^.alloc_chunk_cb(session,len);
 Move(data^,Result.data^,len);
end;

function _pong_data_source(session:PfpWebsocket_session;
                     source:PfpWebsocket_data_provider;
                     frame_len:size_t;
                     block:Pio_block):ssize_t;
var
 frame:PPing_frame;
begin
 if source^.data=nil then Exit(WS_CB_ERR);
 frame:=PPing_frame(frame_queue_pop(@PPing_node(source^.data)^.queue));
 if frame=nil then
 begin
  Result:=PPing_node(source^.data)^.flag;
 end else
 begin
  Result:=WS_CB_CON;
  block^:=frame^.data;
  FreeMem(frame);
 end;
end;

function _pong_close_source(session:PfpWebsocket_session;
                      source:PfpWebsocket_data_provider):ssize_t;
begin
 Result:=WS_CB_FIN;
 if source^.data=nil then Exit(WS_CB_ERR);
 frame_queue_clear(@PPing_node(source^.data)^.queue);
 FreeMem(source^.data);
end;

function rfc6455_mem_recv(session:PfpWebsocket_session;data:Pointer;len:size_t):size_t;
label
 jmp_begin,
 jmp_frame_size1,
 jmp_frame_size2,
 jmp_len_word,
 jmp_mask1,
 jmp_mask2,
 jmp_1_14,
 jmp_1_15,
 jmp_2_15,
 jmp_2_16,
 jmp_3_16,
 jmp_data;

 function _min(o,t:size_t):size_t; inline;
 begin
  if o<t then Result:=o else Result:=t;
 end;

 procedure rfc6455_recv_ping(data:Pointer;pos,len:size_t;is_end:Boolean); inline;
 var
  Ping_frame:PPing_frame;
  data_prd:TfpWebsocket_data_provider;
 begin
  With Prfc6455_session(session)^ do
  if (ping_node=nil) then
  begin
   if (len=0) then
   begin
    fpWebsocket_session_submit_frame_stream(session,nil,0,$0A);
   end else
   if is_end then
   begin
    if (recv_frame[1] and $80)<>0 then
    begin
     _masked(data,pos,len,recv_mask);
    end;
    fpWebsocket_session_submit_frame(session,data,len,$0A);
   end else
   begin
    //new queue node
    ping_node:=AllocMem(SizeOf(TPing_node));
    frame_queue_init(@ping_node^.queue);
    ping_node^.flag:=WS_CB_PAU;

    if (recv_frame[1] and $80)<>0 then
    begin
     _masked(data,pos,len,recv_mask);
    end;

    //new frame
    Ping_frame:=AllocMem(SizeOf(TPing_frame));
    Ping_frame^.data:=_new_chunk(session,data,len);

    frame_queue_push(@ping_node^.queue,Psubmit_frame(Ping_frame));

    //submit node
    data_prd.data:=ping_node;
    data_prd.user:=nil;
    data_prd.close_cb:=@_pong_close_source;
    data_prd.read_cb :=@_pong_data_source;
    fpWebsocket_session_submit_frame_stream(session,@data_prd,recv.FrameSize,$0A);

   end;
  end else
  begin
   if (len=0) then
   begin
    if is_end then
    begin
     ping_node^.flag:=WS_CB_FIN;
     ping_node:=nil;
    end;
    Exit;
   end;
   //new frame
   Ping_frame:=AllocMem(SizeOf(TPing_frame));
   Ping_frame^.data.len:=len;
   Ping_frame^.data.data:=GetMem(len);
   Ping_frame^.data.free:=@System.Freemem;
   Ping_frame^.data.user:=nil;

   if (recv_frame[1] and $80)<>0 then
   begin
    _masked(data,pos,len,recv_mask);
   end;
   Move(data^,Ping_frame^.data.data^,len);
   frame_queue_push(@ping_node^.queue,Psubmit_frame(Ping_frame));

   if is_end then
   begin
    ping_node^.flag:=WS_CB_FIN;
    ping_node:=nil;
   end;

  end;
 end;

 function rfc6455_recv_chunk(data:Pointer;pos,len:size_t;is_end:Boolean):Boolean; inline;
 var
  f:size_t;

 begin
  Result:=False;
  With Prfc6455_session(session)^ do
  begin

   case (recv_frame[0] and $F) of
    $01:f:=WS_FLAG_TXT;
    $02:f:=0;
    $09:begin //ping
         rfc6455_recv_ping(data,pos,len,is_end);
         Exit;
        end;
      { $0A:begin
          if (recv_frame[1] and $80)<>0 then
          begin
           _masked(data,pos,len,recv_mask);
          end;
          Writeln('pong:',GetStr(data,len)); //pong
          Exit;
         end;}
    else Exit;
   end;

   if ((len=0) and (not is_end)) or (message_cb=nil) then Exit;

   f:=f or flags;
   if is_end then
   begin
    f:=f or WS_FLAG_FIN;
   end;

   if (recv_frame[1] and $80)<>0 then
   begin
    _masked(data,pos,len,recv_mask);
   end;

   case message_cb(session,data,len,f) of
    WS_CB_FIN:;
    WS_CB_CON:;
    WS_CB_PAU:
    begin
     //ret mask
     if (recv_frame[1] and $80)<>0 then
     begin
      _masked(data,pos,len,recv_mask);
     end;
     Result:=True;
    end;
    else
     begin
      recv.state:=WS_ERR_I_DATA;
      Result:=True;
     end;
   end;

  end;
 end;

var
 i,d,t:size_t;
 b:byte;
begin
 Result:=0;
 if (len=0) then Exit;
 With Prfc6455_session(session)^ do
 begin
  i:=0;
  case recv.state of
    0:;
    1:begin
       recv_frame[1]:=PByte(data)[i]; Inc(i);
       Goto jmp_frame_size1;//next
      end;
    2:begin //word 0
       case (len-i) of
        1:begin
           PByte(@recv.FrameSize)[0]:=PByte(data)[i]; Inc(i);
           recv.state:=3;
           Exit(i);
          end;
        else
           Goto jmp_len_word;
       end;
      end;
    3:begin //word 1
       PByte(@recv.FrameSize)[1]:=PByte(data)[i]; Inc(i);
       recv.FrameSize:=BEtoN(Word(recv.FrameSize));
       Goto jmp_mask1;
      end;
   4..11: //len qword
      begin

       d:=recv.state-4;
       t:=_min(len-i,8-d);

       Dec(t);
       recv.state:=5+t;
       For d:=d to t do
       begin
        PByte(@recv.FrameSize)[d]:=PByte(data)[i]; Inc(i);
       end;
       if recv.state=12 then
       begin
        recv.FrameSize:=BEtoN(recv.FrameSize);
        Goto jmp_mask1;
       end;
       Exit(i);

      end;
   12:Goto jmp_mask2;
   13:begin //mask 1
       case (len-i) of
        1:Goto jmp_1_14;
        2:Goto jmp_1_15;
        else
          begin
           PByte(@recv_mask)[1]:=PByte(data)[i]; Inc(i);
           jmp_2_16:
           PByte(@recv_mask)[2]:=PByte(data)[i]; Inc(i);
           jmp_3_16:
           PByte(@recv_mask)[3]:=PByte(data)[i]; Inc(i);
           Goto jmp_data;
          end;
       end;
      end;
   14:begin //mask 2
       case (len-i) of
        1:Goto jmp_2_15;
        else
          Goto jmp_2_16;
       end;
      end;
   15:begin //mask 3
       Goto jmp_3_16;
      end;
   16:Goto jmp_data;
   else
      begin
       recv.state:=WS_ERR_INTERN;
       Exit(i);
      end;
  end;

  jmp_begin:

  b:=PByte(data)[i];
  if recv_frame[0]<>0 then //PREV IS CONTINUE
  begin
   Case (b and $8F) of
    $00,      //CONTINUE
    $80:;     //FIN CONTINUE
    $88:;     //FIN CLOSE
    $89,$8A:; //FIN ping, pong
    else
     begin
      recv.state:=WS_ERR_PROTOC;
      Exit(i);
     end;
   end;
   recv_frame[0]:=(recv_frame[0] and $0F) or (b and $F0); //MOVE FLAG ONLY
   Inc(i);
   if (i<len) then
   begin
    recv.state:=1;
    Exit(i);
   end;
   recv_frame[1]:=PByte(data)[i];
   Inc(i);
   Goto jmp_frame_size2;//next
  end else
  if (i+1<len) then
  begin
   Word(recv_frame):=PWORD(@PByte(data)[i])^;
   i:=i+2;
   //next
  end else
  begin
   recv_frame[0]:=PByte(data)[i]; Inc(i);
   recv.state:=1;
   Exit(i);
  end;

  jmp_frame_size1:

  case (recv_frame[0] and $8F) of
   $88:;     //FIN CLOSE
   $01,$81,  //BIN
   $02,$82,  //TXT
   $89,$8A:; //FIN ping, pong
   else
   begin
    recv.state:=WS_ERR_UNSUPP;
    Exit(i);
   end;
  end;

  jmp_frame_size2:

  recv.FrameSize:=recv_frame[1] and $7F;
  Case recv.FrameSize of
   126:begin; //next word
        recv.FrameSize:=0;

        case (len-i) of
         0:begin
            recv.state:=2;
            Exit(i);
           end;
         1:begin
            PByte(@recv.FrameSize)[0]:=PByte(data)[i]; Inc(i);
            recv.state:=3;
            Exit(i);
           end;
         else
           begin
            jmp_len_word:
            recv.FrameSize:=PWORD(@PByte(data)[i])^;
            recv.FrameSize:=BEtoN(Word(recv.FrameSize));
            i:=i+2;
           end;
        end;

       end;
   127:begin; //next qword
        recv.FrameSize:=0;

        t:=(len-i);
        case t of
         0:begin
            recv.state:=4;
            Exit(i);
           end;
         1..7:
           begin //5..11
            Dec(t);
            recv.state:=5+t;
            For d:=0 to t do
            begin
             PByte(@recv.FrameSize)[d]:=PByte(data)[i]; Inc(i);
            end;
            Exit(i);
           end;
         else
           begin
            recv.FrameSize:=PQWORD(@PByte(data)[i])^;
            recv.FrameSize:=BEtoN(recv.FrameSize);
            i:=i+8;
           end;
        end;

       end;
  end;

  jmp_mask1:

  if (recv_frame[1] and $80)=0 then //is not masked
  begin

   if (flags and WS_FLAG_SRV)<>0 then
   begin
    recv.state:=WS_ERR_PROTOC;
    Exit(i);
   end;

   Goto jmp_data;
  end else
  begin
   if (flags and WS_FLAG_SRV)=0 then
   begin
    recv.state:=WS_ERR_PROTOC;
    Exit(i);
   end;
  end;

  jmp_mask2:

  Case (len-i) of
   0:begin
      recv.state:=12;
      Exit(i);
     end;
   1:begin
      PByte(@recv_mask)[0]:=PByte(data)[i]; Inc(i);
      recv.state:=13;
      Exit(i);
     end;
   2:begin
      PByte(@recv_mask)[0]:=PByte(data)[i]; Inc(i);
      jmp_1_14:
      PByte(@recv_mask)[1]:=PByte(data)[i]; Inc(i);
      recv.state:=14;
      Exit(i);
     end;
   3:begin
      PByte(@recv_mask)[0]:=PByte(data)[i]; Inc(i);
      jmp_1_15:
      PByte(@recv_mask)[1]:=PByte(data)[i]; Inc(i);
      jmp_2_15:
      PByte(@recv_mask)[2]:=PByte(data)[i]; Inc(i);
      recv.state:=15;
      Exit(i);
     end;
   else
     begin
      recv_mask:=PDWORD(@PByte(data)[i])^;
      i:=i+4;
     end;
  end;

  jmp_data:

  d:=_min(recv.FrameSize-recv.FramePos,len-i);

  case (recv_frame[0] and $F) of
   $08:begin //CLOSE
        if (d>=2) then
        begin
         recv.state:=PWORD(@PByte(data)[i])^;
         Inc(i,2);
         if (recv_frame[1] and $80)<>0 then
         begin
          _masked(@recv.state,0,2,recv_mask);
         end;
         recv.state:=BEtoN(Word(recv.state));
         case recv.state of
          WS_ERR_CLOSED,
          3000..4999:;
          else
           recv.state:=WS_ERR_CLOSED;
         end;
        end else
        begin
         recv.state:=WS_ERR_CLOSED;
        end;
        Exit(i);
       end;
  end;

  t:=recv.FramePos+d;
  Boolean(b):=(t>=recv.FrameSize);

  if rfc6455_recv_chunk(@PByte(data)[i],recv.FramePos,d,Boolean(b) and ((recv_frame[0] shr 7)<>0)) then Exit(i);

  recv.FramePos:=t;
  Inc(i,d);

  if Boolean(b) then
  begin
   recv.FramePos:=0;

   if (recv_frame[0] shr 7)<>0 then //FIN FRAME
   begin
    recv.MesgSize:=0;
    Word(recv_frame):=0;
   end else
   begin
    recv.MesgSize:=recv.MesgSize+recv.FrameSize;
    if (max_messg_size<>0) and (recv.MesgSize>=max_messg_size) then
    begin
     recv.state:=WS_ERR_TO_BIG;
     Exit(i);
    end;
   end;

   if (i>=len) then
   begin
    recv.state:=0;
    Exit(i);
   end else
   begin
    Goto jmp_begin;
   end;

  end else
  begin
   recv.state:=16;
   Exit(i);
  end;


 end;
end;

function _close_node_cb(session:PfpWebsocket_session;node:Psubmit_frame):Boolean;
begin
 Result:=false;
 if Assigned(node^.data_prd.close_cb) then
 begin
  case node^.data_prd.close_cb(session,@node^.data_prd) of
   WS_CB_FIN:;
   WS_CB_CON:;
   WS_CB_PAU:Exit(true); //pause
   else
     begin //error
      session^.send.state:=WS_ERR_INTERN;
      Exit(true);
     end;
  end;
 end;
 submit_frame_free(frame_queue_pop(@session^.send.frame_queue));
end;

function _read_cb(session:PfpWebsocket_session;node:Psubmit_frame;pause_state:SizeUInt):Byte;
begin
 Result:=0;
 if Assigned(node^.data_prd.read_cb) then
 begin
  case node^.data_prd.read_cb(session,@node^.data_prd,node^.frame_len,@session^.send.buf) of
   WS_CB_FIN:
     begin
      Result:=1;
     end;
   WS_CB_PAU:
     begin //pause
      session^.send.state:=pause_state;
      Result:=2;
     end;
   WS_CB_CON:;
   else
     begin
      session^.send.state:=WS_ERR_INTERN;
      Result:=2;
      _close_node_cb(session,node);
     end;
  end;
 end else
 begin
  session^.send.buf:=Default(Tio_block);
  Result:=1;
 end;
end;

function rfc6455_mem_send(session:PfpWebsocket_session;data:Pio_block):size_t;
label
 jmp_begin,jmp_after_open;

var
 node:Psubmit_frame;
 frame_len:qword;
 frame:array[0..13] of Byte;
 L:Byte;

 procedure _encode_len; inline;
 begin
  Case frame_len of
   0..125:
    begin
     frame[1]:=frame[1] or Byte(frame_len);
     L:=2;
    end;
   126..65535:
    begin
     frame[1]:=frame[1] or 126;
     PWORD(@frame[2])^:=NtoBE(Word(frame_len));
     L:=4;
    end;
   else
    begin
     frame[1]:=frame[1] or 127;
     PQWORD(@frame[2])^:=NtoBE(frame_len);
     L:=10;
    end;
  end;
 end;

begin
 Result:=0;
 With Prfc6455_session(session)^ do
 begin
  Case send.state of
   1:begin
      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then
      begin
       session^.send.state:=WS_ERR_INTERN;
       Exit;
      end;
      Goto jmp_after_open;
     end;
   2,      //continue, fetch buf
   3:begin //continue, fetch buf FIN
      Result:=send.buf.len;
      data^:=send.buf;
      send.buf:=Default(Tio_block);

      if (flags and WS_FLAG_SRV)=0 then //is client masked
      begin
       _masked(data^.data,0,data^.len,send_mask);
      end;

      send.MesgSize:=send.MesgSize+Result;

      if (send.state=3) then
      begin
       _close_node_cb(session,node);
       send.state:=0;
       Exit;
      end;

      send.state:=4;
      Exit;
     end;
   4:begin //continue, new frame

      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then
      begin
       session^.send.state:=WS_ERR_INTERN;
       Exit;
      end;

      frame[0]:=0;
      Case _read_cb(session,node,4) of
       0:if send.buf.len=0 then Exit; //skip frame
       1:frame[0]:=$80; //FIN
       2:Exit;
      end;

      frame_len:=send.buf.len;

      _encode_len;
      if (flags and WS_FLAG_SRV)=0 then //is client masked
      begin
       send_mask:=_gen_mask;
       PDWORD(@frame[L])^:=send_mask;
       L:=L+4;
      end;

      data^:=_new_chunk(session,@frame,L);
      Result:=L;

      if ((frame[0] and $80)<>0) then
      begin
       if (frame_len=0) then
       begin
        _close_node_cb(session,node);
        send.state:=0;
       end else
       begin
        send.state:=3;
       end;
      end else
      begin
       send.state:=2;
      end;

      Exit;
     end;
   5:begin //data frame

      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then
      begin
       session^.send.state:=WS_ERR_INTERN;
       Exit;
      end;

      Case _read_cb(session,node,5) of
       0:frame[0]:=0;
       1:frame[0]:=$80; //FIN
       2:Exit;
      end;

      frame_len:=node^.frame_len-send.MesgSize;

      if send.buf.len>frame_len then
      begin
       send.state:=WS_ERR_INTERN;
       _close_node_cb(session,node);
       Exit;
      end;

      Result:=send.buf.len;
      data^:=send.buf;
      send.buf:=Default(Tio_block);

      if (flags and WS_FLAG_SRV)=0 then //is client masked
      begin
       _masked(data^.data,send.MesgSize,data^.len,send_mask);
      end;

      send.MesgSize:=send.MesgSize+Result;
      fetch_sub(send.frame_amount,Result);

      if (frame[0]<>0) then
      begin

       if send.MesgSize<>node^.frame_len then
       begin
        send.state:=WS_ERR_INTERN;
       end;

       if node^.op_code=$8 then //IS CLOSE
       begin
        send.state:=WS_ERR_CLOSED;
       end;

       _close_node_cb(session,node);
       send.state:=0;
      end;

      Exit;
     end;
   0:begin
      jmp_begin:
      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then Exit;

      jmp_after_open:

      frame[0]:=node^.op_code;

      case frame[0] of
       $1:;//TXT
       $2:;//BIN
       $9:;//PING
       $A:;//PONG
       $8:begin//CLOSE
           frame[0]:=$88;
           frame[1]:=0;

           L:=2;
           if (flags and WS_FLAG_SRV)=0 then //is client masked
           begin
            frame[1]:=frame[1] or $80;
            PWORD(@frame[L])^:=_gen_mask;
            L:=L+4;
           end;

           data^:=_new_chunk(session,@frame,L);
           Result:=L;

           if (frame_len=0) or (node^.data_prd.read_cb=nil) then
           begin
            if _close_node_cb(session,node) then Exit;
            send.state:=WS_ERR_CLOSED;
           end else
           begin
            send.state:=5;
            send.MesgSize:=0;
           end;
           Exit;
          end;
       else
          begin
           //skip unknow opcode node
           if _close_node_cb(session,node) then Exit;
           Goto jmp_begin;
          end;
      end;

      frame_len:=node^.frame_len;

      if (flags and WS_FLAG_SRV)=0 then //is client masked
      begin
       frame[1]:=$80;
      end else
      begin
       frame[1]:=0;
      end;

      if (frame_len=0) then
      begin

       if (node^.data_prd.read_cb<>nil) then
       begin
        //coninues frame

        Case _read_cb(session,node,1) of
         0:begin
            if (send.buf.len=0) then
            begin
             //skip frame
             send.state:=4;
            end else
            begin
             send.state:=2;
            end;
           end;
         1:begin
            frame[0]:=frame[0] or $80; //FIN
            if (send.buf.len=0) then
            begin
             //space frame
             _close_node_cb(session,node);
             send.state:=0;
            end else
            begin
             send.state:=3;
            end;
           end;
         2:Exit;
        end;

        frame_len:=send.buf.len;
        send.MesgSize:=send.buf.len;
       end else
       begin
        //space frame
        frame[0]:=frame[0] or $80; //FIN
        _close_node_cb(session,node);
        send.state:=0;
       end;

      end else
      begin
       frame[0]:=frame[0] or $80; //FIN
       send.state:=5;
       send.MesgSize:=0;
      end;

       _encode_len;

      if (flags and WS_FLAG_SRV)=0 then //is client masked
      begin
       send_mask:=_gen_mask;
       PDWORD(@frame[L])^:=send_mask;
       L:=L+4;
      end;

      data^:=_new_chunk(session,@frame,L);
      Result:=L;
      Exit;

     end;
  end;
 end;
end;

function hixie_mem_recv(session:PfpWebsocket_session;data:Pointer;len:size_t):size_t;
label
 jmp_begin,jmp_read_size,jmp_data;
var
 i:size_t;
 f:SizeInt;
 d,t:size_t;
 b:Byte;

 function _min(o,t:size_t):size_t; inline;
 begin
  if o<t then Result:=o else Result:=t;
 end;

 function hixie_recv_chunk(data:Pointer;len:size_t;is_end:Boolean):Boolean;
 var
  f:size_t;
 begin
  Result:=False;
  With Phixie_session(session)^ do
  begin
   if ((len=0) and (not is_end)) or (message_cb=nil) then Exit;

   f:=flags;

   if is_end then
   begin
    f:=f or WS_FLAG_FIN;
   end;

   case recv_frame of
    $00:f:=f or WS_FLAG_TXT;
    $80:;
    else Exit;
   end;

   case message_cb(session,data,len,f) of
    WS_CB_FIN:;
    WS_CB_CON:;
    WS_CB_PAU:Result:=True;
    else
     begin
      recv.state:=WS_ERR_I_DATA;
      Result:=True;
     end;
   end;

  end;
 end;

begin
 Result:=0;
 if (len=0) then Exit;
 i:=0;
 With Phixie_session(session)^ do
  case recv.state of
   0:begin
      jmp_begin:
      recv_frame:=PByte(data)^;
      Inc(i);
      case recv_frame of
       $FF:begin
            if (i>=len) or (PByte(data)[i]<>$00) then
            begin
             Inc(i);
             recv.state:=WS_ERR_CLOSED;
            end else
            begin
             recv.state:=WS_ERR_PROTOC;
            end;
            Exit(i);
           end;
       $00:begin
            f:=IndexByte(PByte(data)[i],len-i,$FF);
            if f=-1 then
            begin
             f:=len-i;

             if (max_messg_size<>0) and (f>=max_messg_size) then
             begin
              recv.state:=WS_ERR_TO_BIG;
              Exit(i);
             end;

             if hixie_recv_chunk(@PByte(data)[i],f,false) then
             begin
              recv.state:=1;
              Exit(i);
             end;

             recv.state:=1;
             recv.MesgSize:=f;
             Exit(len);
            end else
            begin

             if (max_messg_size<>0) and (f>=max_messg_size) then
             begin
              recv.state:=WS_ERR_TO_BIG;
              Exit(i);
             end;

             if hixie_recv_chunk(@PByte(data)[i],f,true) then
             begin
              recv.state:=1;
              Exit(i);
             end;

             i:=i+f+1;
             if (i>=len) then Exit(i);
             Goto jmp_begin;
            end;
           end;
       $80:begin
            recv.FramePos:=0;
            recv.FrameSize:=0;

            jmp_read_size:
            repeat
             b:=PByte(data)[i];
             recv.FrameSize:=(recv.FrameSize shl 7) or (b and $7F);
             Inc(i);

             if (max_messg_size<>0) and (recv.FrameSize>=max_messg_size) then
             begin
              recv.state:=WS_ERR_TO_BIG;
              Exit(i);
             end;

             if (b and $80)=0 then //end size
             begin
              Break;
             end;

             if (i>=len) then
             begin
              recv.state:=3;
              Exit(i);
             end;
            until false;

            jmp_data:

            d:=_min(recv.FrameSize-recv.FramePos,len-i);

            t:=recv.FramePos+d;
            Boolean(b):=(t>=recv.FrameSize);
            if hixie_recv_chunk(@PByte(data)[i],d,Boolean(b)) then
             begin
              recv.state:=4;
              Exit(i);
             end;
            recv.FramePos:=t;
            Inc(i,d);

            if Boolean(b) then
            begin
             recv.FramePos:=0;
             recv.state:=0;
             if (i>=len) then
             begin
              Exit(i);
             end else
             begin
              Goto jmp_begin;
             end;
            end else
            begin
             recv.state:=4;
             Exit(i);
            end;

           end;
       else
       begin
        recv.state:=WS_ERR_UNSUPP;
        Exit(i);
       end;
      end;
     end;
   1:begin
      f:=IndexByte(data^,len,$FF);
      if f=-1 then
      begin
       recv.MesgSize:=recv.MesgSize+len;

       if (max_messg_size<>0) and (recv.MesgSize>=max_messg_size) then
       begin
        recv.state:=WS_ERR_TO_BIG;
        Exit(i);
       end;

       if hixie_recv_chunk(data,len,false) then Exit(i);
       Exit(len);
      end else
      begin
       recv.MesgSize:=recv.MesgSize+f;

       if (max_messg_size<>0) and (recv.MesgSize>=max_messg_size) then
       begin
        recv.state:=WS_ERR_TO_BIG;
        Exit(i);
       end;

       if hixie_recv_chunk(data,f,true) then Exit(i);
       i:=f+1;
       recv.state:=0;
       if (i>=len) then Exit(i);
       Goto jmp_begin;
      end;
     end;
   3:Goto jmp_read_size;
   4:Goto jmp_data;
   else
      begin
       recv.state:=WS_ERR_INTERN;
       Exit(i);
      end;
  end;

end;

function hixie_mem_send(session:PfpWebsocket_session;data:Pio_block):size_t;
Label
 jmp_begin;
var
 node:Psubmit_frame;
 frame_len:qword;
 frame:array[0..10] of Byte;
 L:Byte;

 procedure _encode_len(frame_len:qword); inline;
 begin
  repeat
   frame[L]:=Byte(frame_len and $7F);
   frame_len:=frame_len shr 7;
   if (frame_len=0) then
   begin
    Inc(L);
    break;
   end else
   begin
    frame[L]:=frame[L] or $80;
    Inc(L);
   end;
  until false;
 end;

begin
 Result:=0;


 With Phixie_session(session)^ do
 begin
  Case send.state of
   1:begin //txt frame
      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then
      begin
       send.state:=WS_ERR_INTERN;
       Exit;
      end;

      Case _read_cb(session,node,1) of
       0:;
       1:send.state:=2;  //FIN
       2:Exit;
      end;

      frame_len:=node^.frame_len;

      if (frame_len<>0) and (send.buf.len>frame_len-send.MesgSize) then
      begin
       send.state:=WS_ERR_INTERN;
       _close_node_cb(session,node);
       Exit;
      end;

      if IndexByte(send.buf.data^,send.buf.len,$FF)<>-1 then
      begin
       send.state:=WS_ERR_I_DATA;
       _close_node_cb(session,node);
       Exit;
      end;

      Result:=send.buf.len;
      data^:=send.buf;
      send.buf:=Default(Tio_block);

      send.MesgSize:=send.MesgSize+Result;
      fetch_sub(send.frame_amount,Result);
      Exit;
     end;
   2:begin //txt frame fin
      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then
      begin
       send.state:=WS_ERR_INTERN;
       Exit;
      end;

      frame[0]:=$FF;
      L:=1;
      data^:=_new_chunk(session,@frame,L);
      Result:=L;

      send.state:=0;
      _close_node_cb(session,node);
      Exit;
     end;
   3:begin //bin frame
      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then
      begin
       send.state:=WS_ERR_INTERN;
       Exit;
      end;

      Case _read_cb(session,node,1) of
       0:;
       1:send.state:=0;  //FIN
       2:Exit;
      end;

      frame_len:=node^.frame_len;

      if (frame_len<>0) and (send.buf.len>frame_len-send.MesgSize) then
      begin
       send.state:=WS_ERR_INTERN;
       _close_node_cb(session,node);
       Exit;
      end;

      if IndexByte(send.buf.data^,send.buf.len,$FF)<>-1 then
      begin
       send.state:=WS_ERR_I_DATA;
       _close_node_cb(session,node);
       Exit;
      end;

      Result:=send.buf.len;
      data^:=send.buf;
      send.buf:=Default(Tio_block);

      send.MesgSize:=send.MesgSize+Result;
      fetch_sub(send.frame_amount,Result);

      if (send.state=0) then
      begin
       _close_node_cb(session,node);
      end;

      Exit;
     end;
   0:begin
      jmp_begin:
      node:=frame_queue_peek(@send.frame_queue);
      if node=nil then Exit;

      frame[0]:=node^.op_code;

      case frame[0] of
       $1:begin//TXT
           if (node^.frame_len=0) and (node^.data_prd.read_cb=nil) then
           begin
            frame[0]:=$00;
            frame[1]:=$FF;
            L:=2;
            if _close_node_cb(session,node) then Exit;
           end else
           begin
            send.MesgSize:=0;
            send.state:=1;
            frame[0]:=$00;
            L:=1;
           end;

           data^:=_new_chunk(session,@frame,L);
           Result:=L;
           Exit;
          end;
       $2:begin//BIN
           if (node^.frame_len=0) then
           begin
            frame[0]:=$80;
            frame[1]:=$00;
            L:=2;
            if _close_node_cb(session,node) then Exit;
           end else
           begin
            send.MesgSize:=0;
            send.state:=3;
            frame[0]:=$80;
            L:=1;
            frame_len:=node^.frame_len;
            _encode_len(frame_len);
           end;

           data^:=_new_chunk(session,@frame,L);
           Result:=L;
           Exit;
          end;
       $8:begin//CLOSE
           frame[0]:=$FF;
           frame[1]:=$00;
           L:=2;

           data^:=_new_chunk(session,@frame,L);
           Result:=L;

           if _close_node_cb(session,node) then Exit;
           send.state:=WS_ERR_CLOSED;
           Exit;
          end;
       else
          begin
           //skip unknow opcode node
           if _close_node_cb(session,node) then Exit;
           Goto jmp_begin;
          end;
      end;

     end;

  end;

 end;

end;

function _std_alloc_chunk(session:PfpWebsocket_session;len:size_t):Tio_block;
begin
 Result.len:=len;
 Result.data:=GetMem(len);
 Result.free:=@System.Freemem;
 Result.user:=nil;
end;

Const
 rfc6455_proto_cbs:TfpWebsocket_session.Tws_proto_cbs=(
  recv_cb:@rfc6455_mem_recv;
  send_cb:@rfc6455_mem_send;
 );

 hixie_proto_cbs:TfpWebsocket_session.Tws_proto_cbs=(
  recv_cb:@hixie_mem_recv;
  send_cb:@hixie_mem_send;
 );

function  fpWebsocket_session_new(Var session:PfpWebsocket_session;flags:size_t):Boolean;
begin
 Result:=false;
 session:=nil;
 if (flags and WS_FLAG_HIX)<>0 then
 begin
  session:=AllocMem(SizeOf(Thixie_session));
  if (session=nil) then Exit;
  session^.protos:=@hixie_proto_cbs;
 end else
 begin
  session:=AllocMem(SizeOf(Trfc6455_session));
  if (session=nil) then Exit;
  session^.protos:=@rfc6455_proto_cbs;
 end;
 session^.alloc_chunk_cb:=@_std_alloc_chunk;
 session^.max_messg_size:=DEF_MAX_MESSG_SIZE;
 session^.flags:=flags and (not 3);
 frame_queue_init(@session^.send.frame_queue);
 Result:=true;
end;

function  fpWebsocket_session_new(Var session:PfpWebsocket_session;option:PfpWebsocket_handshake):Boolean;
begin
 Result:=false;
 if (option=nil) then Exit;
 session:=nil;
 Case option^.state of
  ST_SRV_SLCT:
   case option^.version of
    7,8,13:
       begin
        Result:=fpWebsocket_session_new(session,WS_FLAG_SRV);
       end;
    75,
    76:begin
        Result:=fpWebsocket_session_new(session,WS_FLAG_SRV or WS_FLAG_HIX);
       end;
   end;

  ST_CLN_CHCK:
   case option^.version of
    7,8,13:
        begin
         Result:=fpWebsocket_session_new(session,0);
        end;
    75,
    76: begin
         Result:=fpWebsocket_session_new(session,WS_FLAG_HIX);
        end;
   end;
 end;
end;

procedure fpWebsocket_session_del(session:PfpWebsocket_session);
begin
 if (session=nil) then Exit;
 frame_queue_clear(@session^.send.frame_queue);
 io_block_free(@session^.send.buf);
 if (session^.flags and WS_FLAG_HIX)=0 then
 With Prfc6455_session(session)^ do
 if ping_node<>nil then
 begin
  frame_queue_clear(@ping_node^.queue);
  FreeMem(ping_node);
 end;
 FreeMem(session);
end;

function  fpWebsocket_session_get_user_data(session:PfpWebsocket_session):Pointer;
begin
 Result:=nil;
 if (session=nil) then Exit;
 Result:=session^.user_data;
end;

procedure fpWebsocket_session_set_user_data(session:PfpWebsocket_session;data:Pointer);
begin
 if (session=nil) then Exit;
 session^.user_data:=data;
end;

procedure fpWebsocket_session_set_message_cb(session:PfpWebsocket_session;cb:TWebsocket_message_callback);
begin
 if (session=nil) then Exit;
 session^.message_cb:=cb;
end;

procedure fpWebsocket_session_set_alloc_chunk_cb(session:PfpWebsocket_session;cb:TWebsocket_alloc_chunk_callback);
begin
 if (session=nil) then Exit;
 if cb=nil then
  session^.alloc_chunk_cb:=@_std_alloc_chunk
 else
  session^.alloc_chunk_cb:=cb;
end;

function fpWebsocket_session_mem_recv(session:PfpWebsocket_session;data:Pointer;len:size_t):ssize_t;
begin
 Result:=-1;
 if (session=nil) or (session^.protos^.recv_cb=nil) then Exit;
 if session^.recv.state>=WS_ERR_CLOSED then Exit;
 Result:=0;
 if (data=nil) or (len=0) then Exit;
 Result:=session^.protos^.recv_cb(session,data,len);
end;

function fpWebsocket_session_mem_send(session:PfpWebsocket_session;data:Pio_block):ssize_t;
begin
 Result:=-1;
 if (session=nil) or (session^.protos^.send_cb=nil) then Exit;
 if session^.send.state>=WS_ERR_CLOSED then Exit;
 Result:=0;
 if (data=nil) then Exit;
 Result:=session^.protos^.send_cb(session,data);
end;

function fpWebsocket_session_get_recv_err(session:PfpWebsocket_session):size_t;
begin
 Result:=WS_ERR_CLOSED;
 if (session=nil) then Exit;
 if session^.recv.state>=WS_ERR_CLOSED then
  Result:=session^.recv.state
 else
  Result:=WS_ERR_OPENED;
end;

function fpWebsocket_session_get_send_err(session:PfpWebsocket_session):size_t;
begin
 Result:=WS_ERR_CLOSED;
 if (session=nil) then Exit;
 if session^.send.state>=WS_ERR_CLOSED then
  Result:=session^.send.state
 else
  Result:=WS_ERR_OPENED;
end;

function  fpWebsocket_session_want_write(session:PfpWebsocket_session):Boolean;
begin
 Result:=false;
 if (session=nil) then Exit;
 if session^.send.state>=WS_ERR_CLOSED then Exit;
 Result:=Assigned(frame_queue_peek(@session^.send.frame_queue))
end;

function  fpWebsocket_session_buffered_Amount(session:PfpWebsocket_session):SizeUint;
begin
 Result:=0;
 if (session=nil) then Exit;
 if session^.send.state>=WS_ERR_CLOSED then Exit;
 Result:=session^.send.frame_amount;
end;

function  fpWebsocket_session_peek_provider(session:PfpWebsocket_session):PfpWebsocket_data_provider;
var
 node:Psubmit_frame;
begin
 Result:=nil;
 if (session=nil) then Exit;
 node:=frame_queue_peek(@session^.send.frame_queue);
 if (node<>nil) then Result:=@node^.data_prd;
end;

function fpWebsocket_session_submit_frame_stream(session:PfpWebsocket_session;data_prd:PfpWebsocket_data_provider;frame_len:size_t;op_code:Byte):Boolean;
var
 node:Psubmit_frame;
begin
 Result:=false;
 if (session=nil) then Exit;
 if session^.send.state>=WS_ERR_CLOSED then Exit;

 node:=AllocMem(SizeOf(Tsubmit_frame));
 if (data_prd<>nil) then
 begin
  node^.data_prd:=data_prd^;
 end;
 node^.frame_len:=frame_len;
 node^.op_code:=op_code;
 Result:=frame_queue_push(@session^.send.frame_queue,Node);
 if Result then
 begin
  fetch_add(session^.send.frame_amount,frame_len);
 end;
end;

function _submit_simple(session:PfpWebsocket_session;
                        source:PfpWebsocket_data_provider;
                        frame_len:size_t;
                        block:Pio_block):ssize_t;
begin
 Result:=WS_CB_FIN;

 block^.data:=source^.data;
 block^.len :=frame_len;
 block^.free:=@System.Freemem;
 block^.user:=nil;

 source^.data:=nil;
end;

function fpWebsocket_session_submit_frame(session:PfpWebsocket_session;data:PAnsiChar;len:size_t;op_code:Byte):Boolean;
var
 data_prd:TfpWebsocket_data_provider;
begin
 Result:=false;
 if (session=nil) then Exit;
 if session^.send.state>=WS_ERR_CLOSED then Exit;

 if (data=nil) or (len=0) then
 begin
  Result:=fpWebsocket_session_submit_frame_stream(session,nil,0,op_code);
 end else
 begin
  data_prd.data    :=GetMem(len);
  data_prd.close_cb:=nil;
  data_prd.read_cb :=@_submit_simple;
  Move(data^,data_prd.data^,len);
  Result:=fpWebsocket_session_submit_frame_stream(session,@data_prd,len,op_code);
 end;

 if not Result then
 begin
  FreeMem(data_prd.data);
 end;
end;

function fpWebsocket_session_submit_text(session:PfpWebsocket_session;data:PAnsiChar;len:size_t):Boolean; inline;
begin
 Result:=fpWebsocket_session_submit_frame(session,data,len,$01);
end;

function fpWebsocket_session_submit_data(session:PfpWebsocket_session;data:Pointer;len:size_t):Boolean; inline;
begin
 Result:=fpWebsocket_session_submit_frame(session,data,len,$02);
end;

function fpWebsocket_session_submit_ping(session:PfpWebsocket_session;data:Pointer;len:size_t):Boolean; inline;
begin
 Result:=true;
 if (session^.flags and WS_FLAG_HIX)=0 then
  Result:=fpWebsocket_session_submit_frame(session,data,len,$09);
end;

function fpWebsocket_session_submit_close(session:PfpWebsocket_session;err_code:Word=0):Boolean;
begin
 Result:=false;
 if (session=nil) then Exit;
 if (session^.flags and WS_FLAG_HIX)<>0 then err_code:=0;
 case err_code of
  WS_ERR_CLOSED,
  3000..4999:
   begin
    err_code:=NToBe(err_code);
    Result:=fpWebsocket_session_submit_frame(session,@err_code,SizeOf(Word),$08);
   end;
  else
   Result:=fpWebsocket_session_submit_frame_stream(session,nil,0,$08);
 end;
end;

end.

