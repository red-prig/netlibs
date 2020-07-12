{ openssl extension to bufferevent

  Copyright (C) 2018-2020 Red_prig

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

unit bufferevent_openssl;

{$mode objfpc}{$H+}

interface

Uses
 atomic,evpool,openssl;

Const
 BUFFEREVENT_SSL_OPEN       = 0;
 BUFFEREVENT_SSL_CONNECTING = 1;
 BUFFEREVENT_SSL_ACCEPTING  = 2;

 BEV_EVENT_SSL_WRITE   =$100;
 BEV_EVENT_SSL_SHUTDOWN=$200;

function bufferevent_openssl_socket_new(base:Pevpool;fd:THandle;ssl:PSSL;state:SizeInt):Pbufferevent;
function bufferevent_openssl_get_ssl(bev:Pbufferevent):PSSL;
function bufferevent_openssl_shutdown(bev:Pbufferevent):Boolean;

implementation

//----openssl----

type
 PBufferevent_sio_ssl=^TBufferevent_sio_ssl;
 TBufferevent_sio_ssl=object(TBufferevent_sio)
  private
   FSSL:PSSL;
   FSSL_RBUF,FSSL_WBUF:Tevbuffer;
   num_read:SizeUint;
 end;

Const
 BIO_TYPE_EVENT=57;

{$IFDEF USE_BIO_ST}
procedure BIO_set_data(a:PBIO;ptr:pointer); inline;
begin
 a^.ptr:=ptr;
end;

function BIO_get_data(a:PBIO):pointer; inline;
begin
 Result:=a^.ptr;
end;

procedure BIO_set_init(a:PBIO;init:cint); inline;
begin
 a^.init:=init;
end;

procedure BIO_set_shutdown(a:PBIO;shut:cint); inline;
begin
 a^.shutdown:=shut;
end;

function BIO_get_shutdown(a:PBIO):cint; inline;
begin
 Result:=a^.shutdown;
end;

function BIO_number_read(bio:PBIO):uint64; inline;
begin
 Result:=bio^.num_read;
end;

function BIO_number_written(bio:PBIO):uint64; inline;
begin
 Result:=bio^.num_write;
end;

procedure BIO_set_flags(b:PBIO;flags:cint); inline;
begin
 b^.flags:=b^.flags or flags;
end;

procedure BIO_clear_flags(b:PBIO;flags:cint); inline;
begin
 b^.flags:=b^.flags and (not flags);
end;

Procedure BIO_set_retry_read(b:PBIO); inline;
begin
 BIO_set_flags(b,BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
end;

Procedure BIO_set_retry_write(b:PBIO); inline;
begin
 BIO_set_flags(b,BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
end;

Procedure BIO_clear_retry_flags(b:PBIO); inline;
begin
 BIO_clear_flags(b,BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

{$ENDIF}

{
function bio_bufferevent_new(b:PBIO):cint; cdecl;
begin
 BIO_set_init(b, 0);
 BIO_set_data(b, nil);
 Result:=1;
end;

function bio_bufferevent_free(b:PBIO):cint; cdecl;
begin
 if not Assigned(b) then Exit(0);
 Result:=1;
end;
}

function bio_bufferevent_read(b:PBIO;_out:pbyte;outlen:cint):cint; cdecl;
Var
 bev:PBufferevent_sio_ssl;
 input:Pevbuffer;
begin
 Result:=0;

 if not Assigned(b) then Exit(-1);

 BIO_clear_retry_flags(b);

 if not Assigned(_out) then Exit;

 bev:=BIO_get_data(b);

 if not Assigned(bev) then Exit;

 input:=nil;
 _be_ops_sio(bev,BEV_CTRL_GET_IE,@input);


 if (bev^.num_read<outlen) then
 begin
  outlen:=bev^.num_read;
 end;

 Result:=evbuffer_remove(input,_out,outlen);

 if (Result=0) then
 begin
  // If there's no data to read, say so.
  BIO_set_retry_read(b);
  Result:=-1;
 end else
 begin
  bev^.num_read:=bev^.num_read-Result;
 end;

end;

{$IFNDEF NO_WATERMARKS}
function WaterMark_hi_output(bev_ssl:PBufferevent_sio_ssl):SizeUInt; inline;
Var
 WM:TWaterMarks;
begin
 WM:=Default(TWaterMarks);
 _be_ops_sio(bev_ssl,BEV_CTRL_GET_WM,@WM);
 Result:=WM.WR.hi;
end;
{$ENDIF}

function bio_bufferevent_write(b:PBIO;_in:pbyte;inlen:cint):cint; cdecl;
Var
 bev:PBufferevent_sio_ssl;
 output:Pevbuffer;
 s,outlen:SizeUInt;
begin
 Result:=-1;

 if not Assigned(b) then Exit;

 BIO_clear_retry_flags(b);

 if not Assigned(_in) then Exit;

 bev:=BIO_get_data(b);

 if not Assigned(bev) then Exit;

 output:=nil;
 _be_ops_sio(bev,BEV_CTRL_GET_OE,@output);

 outlen:=evbuffer_get_length(output);

 {$IFNDEF NO_WATERMARKS}
 s:=WaterMark_hi_output(bev);
 if (s<>0) then
 begin
  { Copy only as much data onto the output buffer as can fit under the
    high-water mark. }
  outlen:=evbuffer_get_length(output);
  if (s<=outlen+inlen) then
  begin

   if (s<=outlen) then
   begin
    inlen:=0;
   end else
   begin
    inlen:=s-outlen;
   end;
  end;
 end;
 {$ENDIF}

 if evbuffer_add(output,_in,inlen) then
 begin
  Result:=inlen;
 end else
 begin
  // If no data can fit, we'll need to retry later.
  BIO_set_retry_write(b);
  Result:=-1;
 end;
end;

function bio_bufferevent_puts(b:PBIO;s:pbyte):cint; cdecl;
begin
 Result:=bio_bufferevent_write(b,s,strlen(PChar(s)));
end;

function bio_bufferevent_ctrl(b:PBIO;cmd:cint;num:clong;ptr:pointer):clong; cdecl;
Var
 bev:PBufferevent_sio_ssl;
 ev:Pevbuffer;
begin
 Result:=0;
 bev:=BIO_get_data(b);
 if not Assigned(bev) then Exit;
 Result:=1;

 Case cmd of
  BIO_CTRL_GET_CLOSE:Result:=BIO_get_shutdown(b);
  BIO_CTRL_SET_CLOSE:BIO_set_shutdown(b,num);
  _BIO_CTRL_PENDING  :
  begin
   ev:=nil;
   _be_ops_sio(bev,BEV_CTRL_GET_IE,@ev);
   Result:=evbuffer_get_length(ev);
   if Result>1 then Result:=1;
  end;
  _BIO_CTRL_WPENDING :
  begin
   ev:=nil;
   _be_ops_sio(bev,BEV_CTRL_GET_OE,@ev);
   Result:=evbuffer_get_length(ev);
   if Result>1 then Result:=1;
  end;
  BIO_CTRL_DUP,
  BIO_CTRL_FLUSH:;//Result:=1;

  else
   Result:=0;
 end;

end;

var
 methods_bufferevent:PBIO_METHOD=nil;

function BIO_s_bufferevent:PBIO_METHOD;
begin
 Result:=load_acquire(methods_bufferevent);
 if Result=nil then
 begin
  Result:=BIO_meth_new(BIO_TYPE_EVENT,'bufferevent');
  ///
  //BIO_meth_set_create (Result, @bio_bufferevent_new);
  //BIO_meth_set_destroy(Result, @bio_bufferevent_free);
  BIO_meth_set_read   (Result, @bio_bufferevent_read);
  BIO_meth_set_write  (Result, @bio_bufferevent_write);
  BIO_meth_set_puts   (Result, @bio_bufferevent_puts);
  BIO_meth_set_ctrl   (Result, @bio_bufferevent_ctrl);
  ///
  if not CAS(methods_bufferevent,nil,Result) then
  begin
   BIO_meth_free(Result);
   Result:=load_acquire(methods_bufferevent);
  end;
 end;
end;

function BIO_new_bufferevent(bev:PBufferevent_sio_ssl):PBIO;
begin
 Result:=nil;
 if not Assigned(bev) then Exit;
 Result:=BIO_new(BIO_s_bufferevent);
 if not Assigned(Result) then Exit;
 BIO_set_init(Result, 1);
 BIO_set_data(Result, bev);
 BIO_set_shutdown(Result, 0);
end;

function  be_ops_ssl_sio_enable(bev_ssl:PBufferevent_sio_ssl):Boolean; forward;
function  be_openssl_eventcb(bev_ssl:PBufferevent_sio_ssl;events:SizeUInt):Boolean; forward;
function  be_openssl_clean(bev_ssl:PBufferevent_sio_ssl):Boolean; forward;
function  be_ops_ssl_sio_write(bev_ssl:PBufferevent_sio_ssl):Boolean; forward;

function be_ops_ssl_sio(bev:Pbufferevent;ctrl_op:SizeInt;ctrl_data:Pointer):Boolean;
begin
 Result:=False;
 Case ctrl_op of
  BEV_CTRL_ENABLE :Result:=be_ops_ssl_sio_enable(PBufferevent_sio_ssl(bev));
  BEV_CTRL_WRITE  :Result:=be_ops_ssl_sio_write(PBufferevent_sio_ssl(bev));

  BEV_CTRL_EVENT  :
  if Assigned(ctrl_data) then
  begin
   Result:=be_openssl_eventcb(PBufferevent_sio_ssl(bev),PSizeUInt(ctrl_data)^);
  end;
  BEV_CTRL_GET_IE :
  if Assigned(ctrl_data) then
  begin
   PPointer(ctrl_data)^:=@PBufferevent_sio_ssl(bev)^.FSSL_RBUF;
   Result:=true;
  end;
  BEV_CTRL_GET_OE :
  if Assigned(ctrl_data) then
  begin
   PPointer(ctrl_data)^:=@PBufferevent_sio_ssl(bev)^.FSSL_WBUF;
   Result:=true;
  end;
  BEV_CTRL_CLEAN  :Result:=be_openssl_clean(PBufferevent_sio_ssl(bev));
  else
   Result:=_be_ops_sio(bev,ctrl_op,ctrl_data);
 end;
end;

function be_openssl_set_state(bev_ssl:PBufferevent_sio_ssl;state:SizeUInt):Boolean; inline;
begin
 With bev_ssl^ do
 begin
  Case state of
   BUFFEREVENT_SSL_ACCEPTING:
   begin
    if SSL_clear(FSSL)=0 then Exit(false);
    SSL_set_accept_state(FSSL);
    Result:=True;
   end;
   BUFFEREVENT_SSL_CONNECTING:
   begin
    if SSL_clear(FSSL)=0 then Exit(false);
    SSL_set_connect_state(FSSL);
    Result:=True;
   end;
   BUFFEREVENT_SSL_OPEN:Result:=True;
   else
    Result:=False;
  end;
 end;
end;

function be_openssl_handshake(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
begin
 Result:=SSL_get_state(bev_ssl^.FSSL)<>TLS_ST_OK;
end;

procedure conn_closed(bev_ssl:PBufferevent_sio_ssl;when,errcode,ret:SizeInt;var events:SizeUint);
Var
 dirty_shutdown:Boolean;
begin

 dirty_shutdown:=false;

 events:=events or BEV_EVENT_ERROR;

 Case errcode of
  SSL_ERROR_ZERO_RETURN: // Possibly a clean shutdown.
   if (SSL_get_shutdown(bev_ssl^.FSSL) and SSL_RECEIVED_SHUTDOWN)<>0 then
   begin
    events:=events or BEV_EVENT_EOF;
   end else
   begin
    dirty_shutdown:=True;
   end;

  SSL_ERROR_SYSCALL: // IO error; possibly a dirty shutdown.
  begin
   if (((ret=0) or (ret=-1)) and (ERR_peek_error()=0)) then
   begin
    dirty_shutdown:=True;
   end;
  end;

  SSL_ERROR_SSL:
  begin
   // Protocol error.
  end;

  SSL_ERROR_WANT_X509_LOOKUP:
  begin
   // XXXX handle this.
  end;

  SSL_ERROR_NONE,
  SSL_ERROR_WANT_READ,
  SSL_ERROR_WANT_WRITE,
  SSL_ERROR_WANT_CONNECT,
  SSL_ERROR_WANT_ACCEPT:;//nothing

  else
  begin
   //Unexpected OpenSSL error
  end;

 end;

 if dirty_shutdown and (when<>BEV_EVENT_EOF) then
 begin
  events:=events or BEV_EVENT_EOF;
 end;

end;

function pending_input(bev_ssl:PBufferevent_sio_ssl):SizeUInt; inline;
Var
 input:Pevbuffer;
begin
 input:=nil;
 _be_ops_sio(bev_ssl,BEV_CTRL_GET_IE,@input);
 Result:=evbuffer_get_length(input);
end;

function do_shutdown(bev_ssl:PBufferevent_sio_ssl;ret:cint):SizeUInt;
var
 err:cint;
begin
 Result:=0;

 ERR_clear_error();
 bev_ssl^.num_read:=pending_input(bev_ssl);

 case ret of
  1:begin //SHUTDOWN has been send
     SSL_set_shutdown(bev_ssl^.FSSL,3);
     bufferevent_shutdown(bev_ssl,1);
     Exit;
    end;
  2:begin //SHUTDOWN has been read
     SSL_set_shutdown(bev_ssl^.FSSL,3);
     bufferevent_shutdown(bev_ssl,0);
     Exit;
    end;
  3:Exit(BEV_EVENT_EOF); //complite
 end;

 ret:=SSL_shutdown(bev_ssl^.FSSL);
 Case ret of
  0:begin //not complite
     _be_ops_sio(bev_ssl,BEV_CTRL_WRITE,nil);
    end;
  1:begin //complite
     bufferevent_shutdown(bev_ssl,2);
    end;
  else
    begin
     err:=SSL_get_error(bev_ssl^.FSSL,ret);
     Case err of
      SSL_ERROR_WANT_READ :begin //no wait to read shutdown
                            bufferevent_shutdown(bev_ssl,0);
                           end;
      SSL_ERROR_WANT_WRITE:begin //need be send
                            _be_ops_sio(bev_ssl,BEV_CTRL_WRITE,nil);
                           end;
      else
      begin
       conn_closed(bev_ssl,BEV_EVENT_EOF,err,ret,Result);
       Exit;
      end;
     end;
    end;
 end;

end;

function do_handshake(bev_ssl:PBufferevent_sio_ssl):SizeUInt;
var
 err,ret:cint;
begin
 Result:=0;
 ERR_clear_error();
 bev_ssl^.num_read:=pending_input(bev_ssl);
 ret:=SSL_do_handshake(bev_ssl^.FSSL);
 if (ret=1) then
 begin
  Result:=BEV_EVENT_CONNECTED;
 end else
 begin
  err:=SSL_get_error(bev_ssl^.FSSL,ret);
  Case err of
   SSL_ERROR_WANT_READ :;//Result:=BEV_EVENT_READING;
   SSL_ERROR_WANT_WRITE:;//Result:=BEV_EVENT_WRITING;
   //SSL_ERROR_WANT_CONNECT,
   //SSL_ERROR_WANT_ACCEPT,
   //SSL_ERROR_WANT_X509_LOOKUP:;
   else
   begin
    conn_closed(bev_ssl,BEV_EVENT_READING,err,ret,Result);
    Exit;
   end;
  end;
 end;

 _be_ops_sio(bev_ssl,BEV_CTRL_READ ,nil);
 _be_ops_sio(bev_ssl,BEV_CTRL_WRITE,nil);

end;

function pending_output(bev_ssl:PBufferevent_sio_ssl):SizeUInt; inline;
Var
 output:Pevbuffer;
begin
 Result:=0;
 if not Assigned(bev_ssl) then Exit;
 output:=nil;
 _be_ops_sio(bev_ssl,BEV_CTRL_GET_OE,@output);
 Result:=evbuffer_get_length(output);
end;

function pending_ssl_output(bev_ssl:PBufferevent_sio_ssl):SizeUInt; inline;
begin
 Result:=0;
 if not Assigned(bev_ssl) then Exit;
 Result:=evbuffer_get_length(@bev_ssl^.FSSL_WBUF);
end;

function pending_ssl_input(bev_ssl:PBufferevent_sio_ssl):SizeUInt; inline;
begin
 Result:=0;
 if not Assigned(bev_ssl) then Exit;
 Result:=evbuffer_get_length(@bev_ssl^.FSSL_RBUF);
end;

function _not_empty_input(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
Var
 input:Pevbuffer;
begin
 input:=nil;
 _be_ops_sio(bev_ssl,BEV_CTRL_GET_IE,@input);
 Result:=not evbuffer_IsEmpty(input);
end;

function _not_empty_ssl_output(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
begin
 Result:=not evbuffer_IsEmpty(@bev_ssl^.FSSL_WBUF);
end;

function _empty_ssl_input(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
begin
 Result:=evbuffer_IsEmpty(@bev_ssl^.FSSL_RBUF);
end;

function _empty_all_output(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
Var
 output:Pevbuffer;
begin
 Result:=evbuffer_IsEmpty(@bev_ssl^.FSSL_WBUF);
 output:=nil;
 _be_ops_sio(bev_ssl,BEV_CTRL_GET_OE,@output);
 Result:=evbuffer_IsEmpty(output) and Result;
end;

function input_contiguous_space(bev_ssl:PBufferevent_sio_ssl):SizeUInt; inline;
Var
 input:Pevbuffer;
begin
 input:=nil;
 _be_ops_sio(bev_ssl,BEV_CTRL_GET_IE,@input);
 Result:=evbuffer_get_contiguous_space(input);
end;

function do_read(bev_ssl:PBufferevent_sio_ssl):SizeUInt;
Var
 rb:SizeUInt;
 buf:Pointer;
 err,ret:cint;
begin
 Result:=0;
 ERR_clear_error();

 bev_ssl^.num_read:=pending_input(bev_ssl);
 if bev_ssl^.num_read=0 then Exit;

 buf:=nil;

 repeat

  //its fucking magick
  rb:=input_contiguous_space(bev_ssl)+SSL_pending(bev_ssl^.FSSL);

  if rb=0 then rb:=32;

  if buf=nil then
  begin
   buf:=GetMem(rb);
  end else
  if MemSize(buf)<rb then
  begin
   FreeMem(buf);
   buf:=GetMem(rb);
  end;

  ret:=SSL_read(bev_ssl^.FSSL,buf, MemSize(buf) );

  if (ret>0) then
  begin

   rb:=MemSize(buf) div 2;
   if (ret>rb) then
   begin
    evbuffer_add_ref(@bev_ssl^.FSSL_RBUF,buf,0,ret,Freemem_ptr);
    buf:=nil;
   end else
   begin
    evbuffer_add(@bev_ssl^.FSSL_RBUF,buf,ret);
   end;

  end else
  begin
   FreeMem(buf);
   err:=SSL_get_error(bev_ssl^.FSSL,ret);
   Case err of
    SSL_ERROR_WANT_READ  :;//Result:=BEV_EVENT_READING;
    SSL_ERROR_WANT_WRITE :;//Result:=BEV_EVENT_WRITING;
    //SSL_ERROR_WANT_CONNECT,
    //SSL_ERROR_WANT_ACCEPT,
    //SSL_ERROR_WANT_X509_LOOKUP:;
    else
    begin
     conn_closed(bev_ssl,BEV_EVENT_READING,err,ret,Result);
     Exit;
    end;
   end;
   Break;
  end;

 until false;


 _be_ops_sio(bev_ssl,BEV_CTRL_READ,nil);

end;

function do_write(bev_ssl:PBufferevent_sio_ssl):SizeUInt;
var
 Node:Piovec;
 size:SizeUInt;
 err,ret,send:cint;
begin
 Result:=0;

 ERR_clear_error();
 size:=evbuffer_get_length(@bev_ssl^.FSSL_WBUF);

 if size=0 then Exit;

 send:=0;

 repeat
  Node:=evbuffer_peek(@bev_ssl^.FSSL_WBUF);
  if not Assigned(Node) then Exit;
  ret:=SSL_write(bev_ssl^.FSSL,iovec_getdata(Node),Node^.len);
  if (ret>0) then
  begin
   if (size<=ret) then
   begin
    size:=0;
   end else
   begin
    size:=size-ret;
   end;

   evbuffer_drain(@bev_ssl^.FSSL_WBUF,ret);
   send:=send+ret;
  end else
  begin
   err:=SSL_get_error(bev_ssl^.FSSL,ret);
   Case err of
    SSL_ERROR_WANT_READ  :;//Result:=BEV_EVENT_READING;
    //SSL_ERROR_WANT_WRITE :;//Result:=BEV_EVENT_WRITING;
    SSL_ERROR_WANT_WRITE:if (send=0) then Result:=BEV_EVENT_SSL_WRITE;
    //SSL_ERROR_WANT_CONNECT,
    //SSL_ERROR_WANT_ACCEPT,
    //SSL_ERROR_WANT_X509_LOOKUP:;
    else
    begin
     conn_closed(bev_ssl,BEV_EVENT_READING,err,ret,Result);
     Exit;
    end;
   end;
   Break;
  end;
 until (size=0);

 _be_ops_sio(bev_ssl,BEV_CTRL_WRITE,nil);

end;

procedure need_write_post(bev_ssl:PBufferevent_sio_ssl); inline;
Var
 events:SizeUInt;
begin
 if _not_empty_ssl_output(bev_ssl) then
 begin
  events:=BEV_EVENT_SSL_WRITE;
  _be_ops_sio(bev_ssl,BEV_CTRL_POST,@events);
 end;
end;

//BEV_EVENT_SSL_WRITE   =$100;
//BEV_EVENT_SSL_SHUTDOWN=$200;

function be_openssl_eventcb(bev_ssl:PBufferevent_sio_ssl;events:SizeUInt):Boolean;// inline;
Var
 be:Boolean;
 Want:SizeUint;

begin
 Result:=false;

 Want:=SSL_get_shutdown(bev_ssl^.FSSL);
 if ((events and BEV_EVENT_SSL_SHUTDOWN)<>0) then
 begin
  events:=events or do_shutdown(bev_ssl,Want);
  if events=0 then Exit;
  Result:=_be_ops_sio(bev_ssl,BEV_CTRL_EVENT,@events);
  Exit;
 end else
 if (Want<>0) then
 begin
  events:=events or do_shutdown(bev_ssl,Want);
  if events=0 then Exit;
  Result:=_be_ops_sio(bev_ssl,BEV_CTRL_EVENT,@events);
  Exit;
 end else
 if ((events and BEV_EVENT_EOE)<>0) then
 begin
  Result:=_be_ops_sio(bev_ssl,BEV_CTRL_EVENT,@events);
  Exit;
 end;

 Want:=0;

 be:=be_openssl_handshake(bev_ssl);

 if be then
 begin
  Want:=do_handshake(bev_ssl);
  Case (Want and (BEV_EVENT_CONNECTED or BEV_EVENT_ERROR)) of
   BEV_EVENT_CONNECTED:
   begin
    Result:=_be_ops_sio(bev_ssl,BEV_CTRL_EVENT,@Want);
    Want:=0;
    be:=False;
   end;
   BEV_EVENT_ERROR:
   begin
    Result:=_be_ops_sio(bev_ssl,BEV_CTRL_EVENT,@Want);
    Exit;
   end;
  end;
 end;

 if not be then
 begin

  if ((events and BEV_EVENT_SSL_WRITE)<>0) then
  begin
   Want:=Want or do_write(bev_ssl);
  end;

  if ((events and BEV_EVENT_WRITING)<>0) then
  begin
   Want:=Want or do_write(bev_ssl);

   if (not _empty_all_output(bev_ssl)) then
   begin
    events:=events and (not BEV_EVENT_WRITING);
   end;

  end;

  if ((events and BEV_EVENT_READING)<>0) then
  begin
   Want:=Want or do_read(bev_ssl);
   if _empty_ssl_input(bev_ssl) then
   begin
    events:=events and (not BEV_EVENT_READING);
   end;

  end;

  if ((Want and BEV_EVENT_SSL_WRITE)<>0) then
  begin
   //post rare case
   need_write_post(bev_ssl);
  end;

  events:=events or (Want and BEV_EVENT_EOE);

  if events=0 then Exit;

  Result:=_be_ops_sio(bev_ssl,BEV_CTRL_EVENT,@events);

 end;
end;

function be_ops_ssl_sio_write(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
begin
 Result:=True;
 need_write_post(bev_ssl);
end;

function be_ops_ssl_sio_enable(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
begin
 Result:=_be_ops_sio(bev_ssl,BEV_CTRL_ENABLE,nil);
 if Result then
 begin
  need_write_post(bev_ssl);
 end;
end;

function  be_openssl_clean(bev_ssl:PBufferevent_sio_ssl):Boolean; inline;
var
 bio:PBIO;
begin
 Result:=true;

 evbuffer_clear(@bev_ssl^.FSSL_RBUF);
 evbuffer_clear(@bev_ssl^.FSSL_WBUF);

 //bio magic time (prevent double free)
 bio:=SSL_get_rbio(bev_ssl^.FSSL);
 BIO_up_ref(bio);
 SSL_set_bio(bev_ssl^.FSSL,nil,nil);
 BIO_free_all(bio);

 SSL_free(bev_ssl^.FSSL);

 Result:=_be_ops_sio(bev_ssl,BEV_CTRL_CLEAN,nil);
end;

function bufferevent_openssl_socket_new(base:Pevpool;fd:THandle;ssl:PSSL;state:SizeInt):Pbufferevent;
var
 bio:PBIO;
begin
 Result:=nil;

 if not Assigned(ssl) then Exit;

 Result:=_bufferevent_sio_new(base,fd,SizeOf(TBufferevent_sio_ssl));
 if Result=nil then Exit;

 With PBufferevent_sio_ssl(Result)^ do
 begin
  be_ops:=@be_ops_ssl_sio;
  FSSL:=ssl;

  evbuffer_init(@FSSL_RBUF);
  evbuffer_init(@FSSL_WBUF);

 end;

 bio:=BIO_new_bufferevent(PBufferevent_sio_ssl(Result));
 SSL_set_bio(ssl,bio,bio);

 SSL_set_mode(ssl,
   SSL_MODE_AUTO_RETRY or
   //SSL_MODE_ASYNC or
   //SSL_MODE_RELEASE_BUFFERS or
   SSL_MODE_ENABLE_PARTIAL_WRITE or
   SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
 );

 be_openssl_set_state(PBufferevent_sio_ssl(Result),state);

end;

function bufferevent_openssl_get_ssl(bev:Pbufferevent):PSSL;
begin
 Result:=nil;
 if Assigned(bev) then
 With PBufferevent_sio_ssl(bev)^ do
  if (be_ops=@be_ops_ssl_sio) then
  begin
   Result:=FSSL;
  end;
end;

function bufferevent_openssl_shutdown(bev:Pbufferevent):Boolean;
Var
 events:SizeUInt;
begin
 Result:=false;
 if Assigned(bev) then
 With PBufferevent_sio_ssl(bev)^ do
  if (be_ops=@be_ops_ssl_sio) then
  begin
   events:=BEV_EVENT_SSL_SHUTDOWN;
   _be_ops_sio(bev,BEV_CTRL_POST,@events);
  end;
end;

end.


