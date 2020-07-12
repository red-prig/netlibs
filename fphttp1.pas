{ http_0.9/1.0/1.1 client/server implimentation similar nghttp2 interface

  Copyright (C) 2019-2020 Red_prig

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

unit fphttp1;

{$mode objfpc}{$H+}

{$DEFINE THREAD_LOCAL_SEND_BLOCK}

interface


uses
 ctypes,nghttp2;

function  fphttp1_magic(data:Pointer;len:SizeUInt):ssize_t;
function  fphttp2_magic(data:Pointer;len:SizeUInt):ssize_t;

function  fphttp1_session_callbacks_new(Var callbacks_ptr:Pnghttp2_session_callbacks):cint;cdecl;
procedure fphttp1_session_callbacks_del(callbacks:Pnghttp2_session_callbacks);cdecl;
procedure fphttp1_session_callbacks_set_send_callback(cbs:Pnghttp2_session_callbacks;send_callback:Tnghttp2_send_callback);cdecl;
procedure fphttp1_session_callbacks_set_recv_callback(cbs:Pnghttp2_session_callbacks;recv_callback:Tnghttp2_recv_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_frame_recv_callback(cbs:Pnghttp2_session_callbacks;on_frame_recv_callback:Tnghttp2_on_frame_recv_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_data_chunk_recv_callback(cbs:Pnghttp2_session_callbacks; on_data_chunk_recv_callback:Tnghttp2_on_data_chunk_recv_callback);cdecl;
procedure fphttp1_session_callbacks_set_before_frame_send_callback(cbs:Pnghttp2_session_callbacks; before_frame_send_callback:Tnghttp2_before_frame_send_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_frame_send_callback(cbs:Pnghttp2_session_callbacks; on_frame_send_callback:Tnghttp2_on_frame_send_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_frame_not_send_callback(cbs:Pnghttp2_session_callbacks; on_frame_not_send_callback:Tnghttp2_on_frame_not_send_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_stream_close_callback(cbs:Pnghttp2_session_callbacks; on_stream_close_callback:Tnghttp2_on_stream_close_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_begin_headers_callback(cbs:Pnghttp2_session_callbacks;on_begin_headers_callback:Tnghttp2_on_begin_headers_callback);cdecl;
Procedure fphttp1_session_callbacks_set_on_header_callback(cbs:Pnghttp2_session_callbacks;on_header_callback:Tnghttp2_on_header_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_invalid_header_callback(cbs:Pnghttp2_session_callbacks; on_invalid_header_callback:Tnghttp2_on_invalid_header_callback);cdecl;
procedure fphttp1_session_callbacks_set_on_begin_frame_callback(cbs:Pnghttp2_session_callbacks; on_begin_frame_callback:Tnghttp2_on_begin_frame_callback);cdecl;
procedure fphttp1_session_callbacks_set_send_data_callback(cbs:Pnghttp2_session_callbacks; send_data_callback:Tnghttp2_send_data_callback);cdecl;
procedure fphttp1_session_callbacks_set_data_source_read_length_callback(cbs:Pnghttp2_session_callbacks;data_source_read_length_callback:Tnghttp2_data_source_read_length_callback);cdecl;

function  fphttp1_option_new(Var option_ptr:Pnghttp2_option):cint;cdecl;
procedure fphttp1_option_del(option:Pnghttp2_option);cdecl;
procedure fphttp1_option_set_peer_max_concurrent_streams(option:Pnghttp2_option;val:uint32);cdecl;
procedure fphttp1_option_set_no_recv_client_magic(option:Pnghttp2_option;val:cint);cdecl;
procedure fphttp1_option_set_no_http_messaging(option:Pnghttp2_option;val:cint);cdecl;
procedure fphttp1_option_set_max_send_header_block_length(option:Pnghttp2_option;val:size_t);cdecl;
procedure fphttp1_option_set_no_closed_streams(option:Pnghttp2_option;val:cint);cdecl;

function  fphttp1_session_server_new (Var session_ptr:Pnghttp2_session;callbacks:Pnghttp2_session_callbacks;user_data:pointer):cint;cdecl;
function  fphttp1_session_server_new2(Var session_ptr:Pnghttp2_session;callbacks:Pnghttp2_session_callbacks;user_data:pointer;option:Pnghttp2_option):cint;cdecl;
//function  fphttp1_session_server_new3(Var session_ptr:Pnghttp2_session;callbacks:Pnghttp2_session_callbacks;user_data:pointer;option:Pnghttp2_option;mem:Pnghttp2_mem):cint;cdecl;

function  fphttp1_session_client_new(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer):cint;cdecl;
function  fphttp1_session_client_new2(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks;user_data:pointer;option:Pnghttp2_option):cint;cdecl;

procedure fphttp1_session_del(session:Pnghttp2_session);cdecl;
function  fphttp1_session_terminate_session(session:Pnghttp2_session;error_code:uint32):cint;cdecl;
function  fphttp1_session_terminate_session2(session:Pnghttp2_session;last_stream_id:int32;error_code:uint32):cint;cdecl;

function  fphttp1_session_get_last_proc_stream_id(session:Pnghttp2_session):int32;cdecl;
function  fphttp1_session_get_outbound_queue_size(session:Pnghttp2_session):size_t;cdecl;
function  fphttp1_session_get_next_stream_id(session:Pnghttp2_session):uint32;cdecl;
function  fphttp1_session_set_next_stream_id(session:Pnghttp2_session;next_stream_id:int32):cint;cdecl;

function  fphttp1_session_want_read(session:Pnghttp2_session):cint;cdecl;
function  fphttp1_session_want_write(session:Pnghttp2_session):cint;cdecl;

function  fphttp1_session_mem_recv(session:Pnghttp2_session;_in:Puint8;inlen:size_t):ssize_t;cdecl;
function  fphttp1_session_mem_send(session:Pnghttp2_session;Var data_ptr:Puint8):ssize_t;cdecl;

function  fphttp1_session_send(session:Pnghttp2_session):cint;cdecl;
function  fphttp1_session_recv(session:Pnghttp2_session):cint;cdecl;

function  fphttp1_session_get_local_settings(session:Pnghttp2_session; id:Tnghttp2_settings_id):uint32;cdecl;

function  fphttp1_submit_settings(session:Pnghttp2_session;flags:uint8;iv:Pnghttp2_settings_entry;niv:size_t):cint;cdecl;
function  fphttp1_submit_response(session:Pnghttp2_session;stream_id:int32;nva:Pnghttp2_nv;nvlen:size_t;data_prd:Pnghttp2_data_provider):cint;cdecl;
function  fphttp1_submit_request(session:Pnghttp2_session;pri_spec:Pnghttp2_priority_spec;nva:Pnghttp2_nv;nvlen:size_t;data_prd:Pnghttp2_data_provider;stream_user_data:pointer):int32;cdecl;
function  fphttp1_submit_headers(session:Pnghttp2_session;flags:uint8;stream_id:int32;pri_spec:Pnghttp2_priority_spec;nva:Pnghttp2_nv;nvlen:size_t;stream_user_data:pointer):int32;cdecl;
function  fphttp1_submit_trailer(session:Pnghttp2_session;stream_id:int32;nva:Pnghttp2_nv;nvlen:size_t):cint;cdecl;
function  fphttp1_submit_data(session:Pnghttp2_session;flags:uint8;stream_id:int32;data_prd:Pnghttp2_data_provider):cint;cdecl;

function  fphttp1_submit_goaway(session:Pnghttp2_session;flags:uint8;last_stream_id:int32;error_code:uint32;opaque_data:Puint8;opaque_data_len:size_t):cint;cdecl;
function  fphttp1_submit_shutdown_notice(session:Pnghttp2_session):cint;cdecl;
function  fphttp1_submit_rst_stream(session:Pnghttp2_session;flags:uint8;stream_id:int32;error_code:uint32):cint;cdecl;

function  fphttp1_session_get_stream_user_data(session:Pnghttp2_session;stream_id:int32):pointer;cdecl;
function  fphttp1_session_set_stream_user_data(session:Pnghttp2_session;stream_id:int32;stream_user_data:pointer):cint;cdecl;
procedure fphttp1_session_set_user_data(session:Pnghttp2_session;user_data:pointer);cdecl;
function  fphttp1_session_find_stream(session:Pnghttp2_session;stream_id:int32):Pnghttp2_stream;cdecl;
function  fphttp1_stream_get_state(stream:Pnghttp2_stream):Tnghttp2_stream_proto_state;cdecl;
function  fphttp1_stream_get_stream_id(stream:Pnghttp2_stream):int32;cdecl;
function  fphttp1_session_check_server_session(session:Pnghttp2_session):cint;cdecl;

function  fphttp1_session_get_root_stream(session:Pnghttp2_session):Pnghttp2_stream;cdecl;
function  fphttp1_stream_get_parent(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;
function  fphttp1_stream_get_next_sibling(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;
function  fphttp1_stream_get_previous_sibling(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;
function  fphttp1_stream_get_first_child(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;

function  fphttp1_session_upgrade(session:Pnghttp2_session;settings_payload:Puint8;settings_payloadlen:size_t;stream_user_data:pointer):cint;cdecl;
function  fphttp1_session_upgrade2(session:Pnghttp2_session;settings_payload:Puint8;settings_payloadlen:size_t;head_request:cint;stream_user_data:pointer):cint;cdecl;


Const
 Scheme_http ='http';
 Scheme_https='https';
 fphttp1_version   =':version';
 fphttp1_http_0_9  ='http/0.9';
 fphttp1_http_1_0  ='http/1.0';
 fphttp1_http_1_1  ='http/1.1';

 fphttp1_connection='connection';
 fphttp1_keep_alive='keep-alive';
 fphttp1_close     ='close';
 fphttp1_te        ='te';
 fphttp1_chunked   ='chunked';
 fphttp1_identity  ='identity';
 fphttp1_URI       ='uri';

type
 Theader_send_callback=function(data:Puint8;length:size_t;user_data:pointer):ssize_t;cdecl;

function nghttp2_send_frame_header(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;
function nghttp2_send_frame_footer(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;

function fphttp1_send_frame_header(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;
function fphttp1_send_frame_footer(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;

implementation

{$IFDEF THREAD_LOCAL_SEND_BLOCK}
 threadvar
  Fblock:Pointer;
{$ENDIF}

Const
 Def_MAX_STREAMS         =8;
 Def_MAX_FRAME_SIZE      =(4*1024);
 Def_MAX_HEADER_LIST_SIZE=20;

 Def_block_len           =(16*1024);

 fphttp1_http_1_0_A='HTTP/1.0 ';
 fphttp1_http_1_1_A='HTTP/1.1 ';
 fphttp1_NL        =#13#10;
 fphttp1_VR        =': ';
 fphttp1_SP        =' ';
 fphttp1_BS        ='/';
 fphttp1_GET_SP    ='GET ';
 fphttp1_con       ='Connection';
 fphttp1_tfe       ='Transfer-Encoding';
 fphttp1_hst       ='Host';
 fphttp_ContL      ='Content-Length';
 fphttp_0          ='0';

 fphttp1_RST_0     ='HTTP/1.0'+fphttp1_NL+'Content-Length:0'+fphttp1_NL+fphttp1_NL;
 fphttp1_RST_1     ='HTTP/1.1'+fphttp1_NL+'Content-Length:0'+fphttp1_NL+fphttp1_NL;

 fpchunk_head      ='0000'+fphttp1_NL;
 fpchunk_eof1      ='0'+fphttp1_NL;
 fpchunk_eof2      ='0'+fphttp1_NL+fphttp1_NL;
 fpchunk_eof3      =fphttp1_NL+'0'+fphttp1_NL+fphttp1_NL;

 fphttp1_server    =$1;
 fphttp1_alive     =$2;

 fphttp1_upgrade   =$4;

 fHost             =$8;
 fConnection       =$10;
 fTransfer         =$20;
 fContentLen       =$40;
 fExpect           =$80;

 fparse_all=fHost or fConnection or fTransfer or fContentLen or fExpect;

 fphttp1_GOAWAY    =$1;
 fphttp1_RST       =$2;
 fphttp1_EXPECT    =$4;
 fphttp1_RECV_CHUNK=$8;
 fphttp1_SEND_CHUNK=$10;
 fphttp1_END_SUBMIT=$20;
 fphttp1_HAS_RESP_D=$40;
 fphttp1_HAS_REQS_D=$80;

{
 <--------         <-OPEN
 header request
 <--------
 [data   request]

 <----->

 >--------        <-HALF CLOSE
 [header expect]
 >--------        <-HALF CLOSE
 header response
 >--------
 [data response]
 >--------        <-CLOSE
}

type
 Pfphttp1_session=^Tfphttp1_session;
 Pfphttp1_stream=^Tfphttp1_stream;
 Pfphttp1_session_callbacks=^Tfphttp1_session_callbacks;

 Tfphttp1_session_callbacks=object
  Fsend_callback:Tnghttp2_send_callback;
  Frecv_callback:Tnghttp2_recv_callback;
  Fon_frame_recv_callback:Tnghttp2_on_frame_recv_callback;
  Fon_data_chunk_recv_callback:Tnghttp2_on_data_chunk_recv_callback;
  Fbefore_frame_send_callback:Tnghttp2_before_frame_send_callback;
  Fon_frame_send_callback:Tnghttp2_on_frame_send_callback;
  Fon_frame_not_send_callback:Tnghttp2_on_frame_not_send_callback;
  Fon_stream_close_callback:Tnghttp2_on_stream_close_callback;
  Fon_begin_headers_callback:Tnghttp2_on_begin_headers_callback;
  Fon_header_callback:Tnghttp2_on_header_callback;
  Fon_invalid_header_callback:Tnghttp2_on_invalid_header_callback;
  Fon_begin_frame_callback:Tnghttp2_on_begin_frame_callback;
  Fsend_data_callback:Tnghttp2_send_data_callback;
  Fsource_read_length_callback:Tnghttp2_data_source_read_length_callback;
 end;

 TNoflags=(f_no_client_magic,f_no_http_messaging,f_no_closed_streams,f_no_free_scheme);
 Pfphttp1_option=^Tfphttp1_option;
 Tfphttp1_option=record
  MAX_STREAMS,
  MAX_FRAME_SIZE:uint32;
  nf:Set of TNoflags;
 end;

 Tfphttp1_parent_stream=object
  Fparent,Fprev,Fnext:Pfphttp1_stream;
  Fstream_id:int32;
  Fuser_data:pointer;
  Fstate:Tnghttp2_stream_proto_state;
 end;

 Tnvp=object
  nva:Pnghttp2_nv;
  nvlen:size_t;
  Procedure free;
  Procedure insert(nv:Tnghttp2_nv);
  Procedure insert_nocopy(name:PAnsiChar;namelen:size_t;value:PAnsiChar;valuelen:size_t); inline;
  procedure _set_value_nocopy(i:size_t;value:PAnsiChar;valuelen:size_t); inline;
  procedure _set_name_nocopy(i:size_t;name:PAnsiChar;namelen:size_t); inline;
  Procedure copy(_nva:Pnghttp2_nv;_nvlen:size_t);
  Procedure clear;
  function  is_clear:Boolean; inline;
  function  render_response_headers(Data:PPointer;sp:ssize_t;Version:Byte):ssize_t;
  function  render_request_headers(Data:PPointer;mp,pp:ssize_t;Version:Byte):ssize_t;
  function  render_trailers(p:ssize_t;Data:PPointer):ssize_t;
 end;

 Tfphttp1_stream=object(Tfphttp1_parent_stream)

  nvp:Tnvp;

  FSend:record
   data_prd:Tnghttp2_data_provider;
   DataSize:Int64;
  end;

  flags:byte;

  procedure SetFlag(f:byte); inline;
  procedure RetFlag(f:byte); inline;
  function  GetFlag(f:byte):Boolean; inline;

  Procedure Clear;

  function  data_use:Boolean;  inline;
  function  is_live:Boolean;   inline;
  function  is_half_close:Boolean; inline;
  function  is_reserved:Boolean; inline;
 end;

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
  Procedure AddChar(C:AnsiChar); inline;
  Procedure AddCharTrimLeft(C:AnsiChar); inline;
  Procedure SetZeroChar; inline;
  Procedure TrimRight;
  Procedure LowerCase;
  function  TryToInt_pos(Out Q:Int64):boolean; inline;
  Procedure TrimLeftUnSafe;
 end;

 Trecv_cb=function(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;
 Tsend_cb=function(session:Pfphttp1_session;P:Pfphttp1_stream;var data:Pointer):ssize_t;

 Tfphttp1_session=object
  Var
   FSettings:packed record
    MAX_STREAMS,
    MAX_FRAME_SIZE,
    MAX_HEADER_LIST_SIZE:uint32;
    scheme:TStrVal;
    nf:Set of TNoflags;
    Version:Byte;
    Fflags:Byte;
   end;
   Fcallbacks:Tfphttp1_session_callbacks;
   Fuser_data:Pointer;
   recv_cb:Trecv_cb;
   send_cb:Tsend_cb;
   Fstreams:record
    parent:Tfphttp1_parent_stream;
    last_stream_id:int32;
    Count:uint32;
   end;
   FHeaders:record
    state:ssize_t;
    last_error:ssize_t;
    FrameSize:Int64;
    DataSize:Int64;
    Count:uint32;
    LastName,
    LastValue:TStrVal;
   end;
   {$IFNDEF THREAD_LOCAL_SEND_BLOCK}
    Fblock:Pointer;
   {$ENDIF}
   FSend:record
    FrameSize:Int64;
    last_error:ssize_t;
   end;
  function  err_recv(err:ssize_t):ssize_t; inline;
  function  err_send(err:ssize_t):ssize_t; inline;
  function  _on_cb_error_recv(err:ssize_t):Boolean;
  function  _on_cb_error_before_send(err:ssize_t):Boolean;
  function  _on_cb_err_fail_send(err:ssize_t):Boolean; inline;
  function  _on_cb_err_fail_recv(err:ssize_t):Boolean; inline;
  function  _on_header(cat:Tnghttp2_headers_category;stream_id:int32;N,V:TStrVal):Boolean;
  function  _on_invalid_header(cat:Tnghttp2_headers_category;stream_id:int32;N,V:TStrVal):Boolean;
  function  _on_header_frame_recv(cat:Tnghttp2_headers_category;flags:uint8;stream_id:int32):Boolean;
  function  _on_data_frame_recv(flags:uint8;stream_id:int32;len:size_t):Boolean;
  function  _on_begin_header_frame(cat:Tnghttp2_headers_category;flags:uint8;stream_id:int32):Boolean;
  function  _on_begin_data_frame(flags:uint8;stream_id:int32;len:size_t):Boolean;
  function  _on_data_chunk_recv(flags:uint8;stream_id:int32;data:Pointer;len:size_t):Boolean; inline;
  function  _on_before_frame_send(cat:Tnghttp2_headers_category;P:Pfphttp1_stream):Boolean;
  function  _on_header_frame_send(cat:Tnghttp2_headers_category;P:Pfphttp1_stream;len:size_t):Boolean;
  function  _on_data_frame_send(stream_id:int32;len:size_t):Boolean;
  function  _on_header_frame_not_send(cat:Tnghttp2_headers_category;P:Pfphttp1_stream):Boolean;
  function  _on_send_data_nocopy(P:Pfphttp1_stream;len:size_t;src:Pnghttp2_data_source;data_flags:uint8):ssize_t;
  function  _on_get_data_source_read_length:ssize_t; inline;

  function  _no_client_magic:Boolean            inline;
  Procedure _err_http_messaging;                inline;
  function  _closed_streams:Boolean;            inline;

  function  _new_stream_id:int32;
  function  _create_stream:Pfphttp1_stream;
  Procedure _close_stream(is_recv:Boolean);
  function  _reserved_stream:boolean; inline;
  function  step_next_stream:Boolean; inline;
  function  resume_stream:Pfphttp1_stream;
  function  pending_stream:boolean; inline;
  procedure drop_stream(is_recv:Boolean);
  function  _on_cb_stream_close(P:Pfphttp1_stream;is_recv:Boolean):Boolean; inline;
  Procedure close_all_streams(todel,is_recv:Boolean); inline;
  Procedure _terminate; inline;
  Procedure nva_config(nva:Pnghttp2_nv;nvlen:size_t);

  procedure SetFlag(f:byte); inline;
  procedure RetFlag(f:byte); inline;
  function  GetFlag(f:byte):Boolean; inline;

  Procedure reset_headers;  inline;
  Procedure reset_parse;    inline;

  Procedure _set_KeepAlive(A:Boolean); inline;
  Procedure __set_version(V:Byte); inline;
  Procedure _set_version(V:Byte;strong:Boolean);
  Procedure _on_field_name; inline;
  Procedure _on_field_content_length; inline;
  Procedure _on_field_cookie(cat:Tnghttp2_headers_category;stream_id:int32); inline;
  Procedure _on_field_request_cb_val(P:Pfphttp1_stream);
  Procedure _on_field_response_cb_val(cat:Tnghttp2_headers_category;P:Pfphttp1_stream);
  Procedure _on_version_cb_09(stream_id:int32);
  Procedure _on_version_cb_val(cat:Tnghttp2_headers_category;stream_id:int32;strong:Boolean);
  Procedure _on_header_cb_val(cat:Tnghttp2_headers_category;stream_id:int32;hname:PChar;len:SizeUint);
  Procedure _on_method_cb_val(P:Pfphttp1_stream); inline;
  Procedure _on_status_cb_val(stream_id:int32); inline;
  function  _parse_char(Ch:AnsiChar):ssize_t;
  function  _headers_end(P:Pfphttp1_stream):Integer; inline;
  function  _send_data_buf(P:Pfphttp1_stream;var data_flags:uint32):ssize_t;
  function  _send_data_nocopy(P:Pfphttp1_stream;len:size_t;var data_flags:uint32):ssize_t;
  function  _send_data_chunk(P:Pfphttp1_stream;var data_flags:uint32):ssize_t;
  procedure _apply_send_FrameSize(P:Pfphttp1_stream;m:ssize_t);
  Procedure _mem_reserve(size:Ptruint);
  Procedure _mem_free; inline;
  procedure  _send_end_stream(is_recv:Boolean); inline;
  function  _check_terminate:Boolean; inline;
  function  _send_header_begin_cb(cat:Tnghttp2_headers_category;P:Pfphttp1_stream):Boolean; inline;
  function  _send_header_end_cb(cat:Tnghttp2_headers_category;P:Pfphttp1_stream;len:size_t):Boolean; inline;
  function  _send_data_end_cb(stream_id:int32;len:size_t):Boolean;
 end;

{
1 GET
2 HEAD
3 POST
4 PUT
5 PATCH
6 DELETE
7 TRACE
8 CONNECT
9 OPTIONS
}

function fphttp1_magic(data:Pointer;len:SizeUInt):ssize_t;
Const
 MinSize=3;

begin
 Result:=0;
 if (data=nil) or (len<MinSize) then Exit;

 if len=3 then
 begin
  Case PDWORD(data)^ and $FFFFFF of
   $00544547:Result:=3; //GET/0
   $00545550:Result:=3; //PUT/0
   $00414548:; //HEA/0
   $00534F50:; //POS/0
   $00544150:; //PAT/0
   $004C4544:; //DEL/0
   $00415254:; //TRA/0
   $004E4F43:; //CON/0
   $0054504F:; //OPT/0
   else      Result:=NGHTTP2_ERR_BAD_CLIENT_MAGIC;
  end;
 end else
 begin
  Case PDWORD(data)^ of
   $20544547:Result:=3; //GET' '
   $20545550:Result:=3; //PUT' '
   $44414548:Result:=4; //HEAD
   $54534F50:Result:=4; //POST
   $43544150:begin //PATC//H
              if len<5 then Exit;
              if PAnsiChar(data)[4]='H' then
              begin
               Result:=5;
              end else
              begin
               Result:=NGHTTP2_ERR_BAD_CLIENT_MAGIC;
              end;
             end;
   $454C4544:begin //DELE//TE
              if len<6 then Exit;
              if PWord(data)[2]=$4554 then //TE
              begin
               Result:=6;
              end else
              begin
               Result:=NGHTTP2_ERR_BAD_CLIENT_MAGIC;
              end;
             end;
   $43415254:begin //TRAC//E
              if len<5 then Exit;
              if PAnsiChar(data)[4]='E' then
              begin
               Result:=5;
              end else
              begin
               Result:=NGHTTP2_ERR_BAD_CLIENT_MAGIC;
              end;
             end;
   else//
    begin
     Result:=NGHTTP2_ERR_BAD_CLIENT_MAGIC;
      if len>=7 then
       Case PQWord(Data)^ and $FFFFFFFFFFFFFF of
        $5443454E4E4F43:Result:=7; //CONNECT
        $534E4F4954504F:Result:=7; //OPTIONS
       end;
    end;
  end;
 end;

end;

function fphttp2_magic(data:Pointer;len:SizeUInt):ssize_t;

 function cmp(buf1:Pointer;buf2:PChar;len:SizeUInt):Boolean; inline;
 begin
  Result:=CompareByte(buf1^,buf2^,len)=0;
 end;

begin
 Result:=0;
 if (data=nil) or (len<Length(NGHTTP2_CLIENT_MAGIC)) then Exit;
 if cmp(data,NGHTTP2_CLIENT_MAGIC,Length(NGHTTP2_CLIENT_MAGIC)) then
 begin
  Result:=Length(NGHTTP2_CLIENT_MAGIC);
 end else
 begin
  Result:=NGHTTP2_ERR_BAD_CLIENT_MAGIC;
 end;
end;

function method_has_request_data(data:Pointer;len:SizeUInt):Boolean; inline;
begin
 Result:=false;
 if (data=nil) then Exit;
 Case len of
  3:Case (PDWord(Data)^ and $FFFFFF) or $202020 of
      $747570:Result:=true; //put
    end;
  4:Case PDWord(Data)^ or $20202020 of
      $74736F70:Result:=true; //post
    end;
  5:Case PDWord(Data)^ or $20202020 of
      $63746170: //patc
                Case PByte(Data)[4] or $20 of
                  $68:Result:=true; //h
                end;
    end;
 end;
end;

function method_has_response_data(data:Pointer;len:SizeUInt):Boolean;
begin
 Result:=false;
 if (data=nil) then Exit;
 Case len of
  3:Case (PDWord(Data)^ and $FFFFFF) or $202020 of
     $746567:Result:=true; //get
    end;
  4:Case PDWord(Data)^ or $20202020 of
     $74736F70:Result:=true; //post
    end;
  5:Case PDWord(Data)^ or $20202020 of
     $63746170: //patc
               Case PByte(Data)[4] or $20 of
                $68:Result:=true; //h
               end;
    end;
  7:Case (PQWord(Data)^ and $FFFFFFFFFFFFFF) or $20202020202020 of
     $7463656E6E6F63:Result:=true; //connect
     $736E6F6974706F:Result:=true; //options
    end;
 end;
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
 if Length(S)>0 then
 begin
  i:=Reserve_z(Length(S));
  Move(PChar(S)^,FStr[i],Length(S));
 end;
end;

Procedure TStrVal.SetZeroChar; inline;
begin
 if FLen<>0 then FStr[FLen]:=#0;
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

Procedure _LowerCase(FStr:PByte;FLen:SizeUInt); inline;
begin
 While (FLen<>0) do
 begin
  if Byte(FStr^-Byte($41))<Byte($1A) then
   FStr^:=FStr^ or Byte($20);
  Inc(FStr);
  Dec(FLen);
 end;
end;

Procedure TStrVal.LowerCase;
begin
 if (FStr=nil) then Exit;
 _LowerCase(PByte(FStr),FLen);
end;

{
function TryPcharToQWord(P:PAnsiChar;Len:SizeUInt;Out Q:QWord):boolean;
Var
 R,T:QWord;
 b:Byte;
begin
 Result:=False;
 if (P=nil) or (Len=0) or (Len>20) then Exit;
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
}

function TryPcharToInt64_pos(P:PAnsiChar;Len:SizeUInt;Out Q:Int64):boolean;
Var
 R,T:Int64;
 b:Byte;
begin
 Result:=False;
 if (P=nil) or (Len=0) or (Len>19) then Exit;
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

function TStrVal.TryToInt_pos(Out Q:Int64):boolean; inline;
begin
 Result:=TryPcharToInt64_pos(FStr,FLen,Q);
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

procedure PcharTrim(var Src:PByte;var Len:size_t);
begin
 if (Src=nil) then Exit;

 while (Len>0) and (PAnsiChar(Src)[Len-1]<=' ') do Dec(Len);
 while (Len>0) and (PAnsiChar(Src)^<=' ') do
 begin
  Inc(Src);
  Dec(Len);
 end;

 if (Len=0) then Src:=nil;
end;

function CopyPchar(Src:PByte;Len:size_t):PByte;
begin
 Result:=nil;
 if (Src=nil) or (Len=0) then Exit;
 Result:=GetMem(Len+1);
 Move(Src^,Result^,Len);
 Result[Len]:=0;
end;

function  fphttp1_session_callbacks_new(Var callbacks_ptr:Pnghttp2_session_callbacks):cint;cdecl;
begin
 Result:=0;
 callbacks_ptr:=AllocMem(SizeOf(Tfphttp1_session_callbacks));
 if callbacks_ptr=nil then Result:=NGHTTP2_ERR_NOMEM;
end;

procedure fphttp1_session_callbacks_del(callbacks:Pnghttp2_session_callbacks);cdecl;
begin
 FreeMem(callbacks);
end;

procedure fphttp1_session_callbacks_set_send_callback(cbs:Pnghttp2_session_callbacks;send_callback:Tnghttp2_send_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fsend_callback:=send_callback;
end;

procedure fphttp1_session_callbacks_set_recv_callback(cbs:Pnghttp2_session_callbacks;recv_callback:Tnghttp2_recv_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Frecv_callback:=recv_callback;
end;

procedure fphttp1_session_callbacks_set_on_frame_recv_callback(cbs:Pnghttp2_session_callbacks;on_frame_recv_callback:Tnghttp2_on_frame_recv_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_frame_recv_callback:=on_frame_recv_callback;
end;

procedure fphttp1_session_callbacks_set_on_data_chunk_recv_callback(cbs:Pnghttp2_session_callbacks;on_data_chunk_recv_callback:Tnghttp2_on_data_chunk_recv_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_data_chunk_recv_callback:=on_data_chunk_recv_callback;
end;

procedure fphttp1_session_callbacks_set_before_frame_send_callback(cbs:Pnghttp2_session_callbacks;before_frame_send_callback:Tnghttp2_before_frame_send_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fbefore_frame_send_callback:=before_frame_send_callback;
end;

procedure fphttp1_session_callbacks_set_on_frame_send_callback(cbs:Pnghttp2_session_callbacks;on_frame_send_callback:Tnghttp2_on_frame_send_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_frame_send_callback:=on_frame_send_callback;
end;

procedure fphttp1_session_callbacks_set_on_frame_not_send_callback(cbs:Pnghttp2_session_callbacks;on_frame_not_send_callback:Tnghttp2_on_frame_not_send_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_frame_not_send_callback:=on_frame_not_send_callback;
end;

procedure fphttp1_session_callbacks_set_on_stream_close_callback(cbs:Pnghttp2_session_callbacks;on_stream_close_callback:Tnghttp2_on_stream_close_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_stream_close_callback:=on_stream_close_callback;
end;

procedure fphttp1_session_callbacks_set_on_begin_headers_callback(cbs:Pnghttp2_session_callbacks;on_begin_headers_callback:Tnghttp2_on_begin_headers_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_begin_headers_callback:=on_begin_headers_callback;
end;

Procedure fphttp1_session_callbacks_set_on_header_callback(cbs:Pnghttp2_session_callbacks;on_header_callback:Tnghttp2_on_header_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_header_callback:=on_header_callback;
end;

procedure fphttp1_session_callbacks_set_on_invalid_header_callback(cbs:Pnghttp2_session_callbacks;on_invalid_header_callback:Tnghttp2_on_invalid_header_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_invalid_header_callback:=on_invalid_header_callback;
end;

procedure fphttp1_session_callbacks_set_on_begin_frame_callback(cbs:Pnghttp2_session_callbacks;on_begin_frame_callback:Tnghttp2_on_begin_frame_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fon_begin_frame_callback:=on_begin_frame_callback;
end;

procedure fphttp1_session_callbacks_set_send_data_callback(cbs:Pnghttp2_session_callbacks;send_data_callback:Tnghttp2_send_data_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fsend_data_callback:=send_data_callback;
end;

procedure fphttp1_session_callbacks_set_data_source_read_length_callback(cbs:Pnghttp2_session_callbacks;data_source_read_length_callback:Tnghttp2_data_source_read_length_callback);cdecl;
begin
 if cbs<>nil then
  Pfphttp1_session_callbacks(cbs)^.Fsource_read_length_callback:=data_source_read_length_callback;
end;

function  fphttp1_option_new(Var option_ptr:Pnghttp2_option):cint;cdecl;
begin
 Result:=0;
 option_ptr:=AllocMem(SizeOf(Tfphttp1_option));
 if option_ptr=nil then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_option(option_ptr)^ do
 begin
  MAX_STREAMS   :=Def_MAX_STREAMS;
  MAX_FRAME_SIZE:=Def_MAX_FRAME_SIZE;
  nf:=[f_no_closed_streams];
 end;
end;

procedure fphttp1_option_del(option:Pnghttp2_option);cdecl;
begin
 FreeMem(option);
end;

procedure fphttp1_option_set_peer_max_concurrent_streams(option:Pnghttp2_option;val:uint32);cdecl;
begin
 if option<>nil then
  Pfphttp1_option(option)^.MAX_STREAMS:=val;
end;

procedure fphttp1_option_set_no_recv_client_magic(option:Pnghttp2_option;val:cint);cdecl;
begin
 if option<>nil then
  With Pfphttp1_option(option)^ do
  Case val of
   0:nf:=nf+[f_no_client_magic];
   else
     nf:=nf-[f_no_client_magic];
  end;
end;

procedure fphttp1_option_set_no_http_messaging(option:Pnghttp2_option;val:cint);cdecl;
begin
 if option<>nil then
  With Pfphttp1_option(option)^ do
  Case val of
   0:nf:=nf+[f_no_http_messaging];
   else
     nf:=nf-[f_no_http_messaging];
  end;
end;

procedure fphttp1_option_set_max_send_header_block_length(option:Pnghttp2_option;val:size_t);cdecl;
begin
 if option<>nil then
  Pfphttp1_option(option)^.MAX_FRAME_SIZE:=val;
end;

//save memory
procedure fphttp1_option_set_no_closed_streams(option:Pnghttp2_option;val:cint);cdecl;
begin
 if option<>nil then
  With Pfphttp1_option(option)^ do
  Case val of
   0:nf:=nf+[f_no_closed_streams];
   else
     nf:=nf-[f_no_closed_streams]; //save
  end;
end;

procedure _session_new(Var session_ptr:Pnghttp2_session;callbacks:Pnghttp2_session_callbacks;user_data:pointer;option:Pnghttp2_option);
begin
 session_ptr:=AllocMem(SizeOf(Tfphttp1_session));
 if Assigned(session_ptr) then
 With Pfphttp1_session(session_ptr)^ do
 begin
  if callbacks<>nil then
   Fcallbacks:=Pfphttp1_session_callbacks(callbacks)^;
  Fuser_data:=user_data;

  FSettings.MAX_STREAMS           :=Def_MAX_STREAMS;
  FSettings.MAX_FRAME_SIZE        :=Def_MAX_FRAME_SIZE;
  FSettings.MAX_HEADER_LIST_SIZE  :=Def_MAX_HEADER_LIST_SIZE;
  FSettings.nf                    :=[];

  if option<>nil then
   With Pfphttp1_option(option)^ do
   begin
    FSettings.MAX_STREAMS           :=MAX_STREAMS;
    FSettings.MAX_FRAME_SIZE        :=MAX_FRAME_SIZE;
    FSettings.nf                    :=nf;
   end;
 end;
end;

function  fphttp1_session_server_new(Var session_ptr:Pnghttp2_session;callbacks:Pnghttp2_session_callbacks;user_data:pointer):cint;cdecl;
begin
 Result:=fphttp1_session_server_new2(session_ptr,callbacks,user_data,nil);
end;

function  fphttp1_session_server_new2(Var session_ptr:Pnghttp2_session;callbacks:Pnghttp2_session_callbacks;user_data:pointer;option:Pnghttp2_option):cint;cdecl;
begin
 Result:=0;
 _session_new(session_ptr,callbacks,user_data,option);
 if session_ptr=nil then
 begin
  Result:=NGHTTP2_ERR_NOMEM;
  Exit;
 end;
 With Pfphttp1_session(session_ptr)^ do
 begin
  Fstreams.last_stream_id:=1;
  Fstreams.parent.Fstream_id:=0;
  Fstreams.parent.Fstate:=NGHTTP2_STREAM_STATE_IDLE;
  FSettings.Fflags:=fphttp1_server or fphttp1_alive;
 end;
end;

{function  fphttp1_session_server_new3(Var session_ptr:Pnghttp2_session;callbacks:Pnghttp2_session_callbacks;user_data:pointer;option:Pnghttp2_option;mem:Pnghttp2_mem):cint;cdecl;
begin
 Result:=fphttp1_session_server_new2(session_ptr,callbacks,user_data,option);
end;}

function  fphttp1_session_client_new(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer):cint;cdecl;
begin
 Result:=fphttp1_session_client_new2(session_ptr,callbacks,user_data,nil);
end;

function  fphttp1_session_client_new2(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks;user_data:pointer;option:Pnghttp2_option):cint;cdecl;
begin
 Result:=0;
 _session_new(session_ptr,callbacks,user_data,option);
 if session_ptr=nil then
 begin
  Result:=NGHTTP2_ERR_NOMEM;
  Exit;
 end;
 With Pfphttp1_session(session_ptr)^ do
 begin
  __set_version(11);
  Fstreams.last_stream_id:=0;
  Fstreams.parent.Fstream_id:=0;
  Fstreams.parent.Fstate:=NGHTTP2_STREAM_STATE_IDLE;
  FSettings.Fflags:=fphttp1_alive;
 end;
end;

procedure fphttp1_session_del(session:Pnghttp2_session);cdecl;
begin
 if session=nil then Exit;
 With Pfphttp1_session(session)^ do
 begin
  if not (f_no_free_scheme in FSettings.nf) then
  begin
   FSettings.scheme.Free;
  end;
  FHeaders.LastName.Free;
  FHeaders.LastValue.Free;
  _mem_free;
  close_all_streams(true,false);
 end;
 FreeMem(session);
end;

function  fphttp1_session_terminate_session(session:Pnghttp2_session;error_code:uint32):cint;cdecl;
begin
 Result:=0;
 if session=nil then Exit(NGHTTP2_ERR_NOMEM);
 Pfphttp1_session(session)^._terminate;
end;

function  fphttp1_session_terminate_session2(session:Pnghttp2_session;last_stream_id:int32;error_code:uint32):cint;cdecl;
begin
 Result:=fphttp1_session_terminate_session(session,error_code);
end;

function  fphttp1_session_get_last_proc_stream_id(session:Pnghttp2_session):int32;cdecl;
Var
 P:Pfphttp1_stream;
begin
 Result:=0;
 if session=nil then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
 begin
  P:=Fstreams.parent.Fnext;
  if (P<>nil) and (not P^.is_reserved) then
  begin
   Result:=P^.Fstream_id;
  end else
  begin
   Result:=Fstreams.last_stream_id;
  end;
 end;
end;

function  fphttp1_session_get_outbound_queue_size(session:Pnghttp2_session):size_t;cdecl;
Var
 S:Pfphttp1_stream;
begin
 Result:=0;
 if session=nil then Exit(0);
 Result:=0;
 S:=Pfphttp1_session(session)^.Fstreams.parent.Fprev;
 While (S<>nil) do
 begin
  if not S^.nvp.is_clear then Result:=Result+1;
  S:=S^.Fnext;
 end;
end;

function  fphttp1_session_get_next_stream_id(session:Pnghttp2_session):uint32;cdecl;
begin
 Result:=0;
 if session=nil then Exit(0);
 With Pfphttp1_session(session)^ do
  Result:=Fstreams.last_stream_id;
end;

function  fphttp1_session_set_next_stream_id(session:Pnghttp2_session;next_stream_id:int32):cint;cdecl;
begin
 Result:=NGHTTP2_ERR_INVALID_ARGUMENT;
 if session=nil then Exit;
 With Pfphttp1_session(session)^ do
  if (GetFlag(fphttp1_server) xor (next_stream_id mod 2=0))
     and (next_stream_id>=Fstreams.last_stream_id) then
  begin
   Fstreams.last_stream_id:=next_stream_id;
   Result:=0;
  end;
end;

Procedure Tfphttp1_stream.Clear; inline;
begin
 Fuser_data:=nil;
 Fstream_id:=0;
 Fstate:=0;

 nvp.clear;

 FSend.data_prd.source.ptr:=nil;
 FSend.data_prd.read_callback:=nil;
 FSend.DataSize:=0;
 flags:=0;
end;

Procedure Tnvp.free; inline;
begin
 clear;
 FreeMem(nva);
 nva:=nil;
end;

Procedure Tnvp.insert(nv:Tnghttp2_nv);
var
 i:size_t;
begin
 i:=nvlen;
 nvlen:=nvlen+1;
 if (nva=nil) then
 begin
  nva:=AllocMem(nvlen*SizeOf(Tnghttp2_nv));
 end else
 if (MemSize(nva)<nvlen*SizeOf(Tnghttp2_nv)) then
 begin
  nva:=ReAllocMem(nva,nvlen*SizeOf(Tnghttp2_nv));
 end;

 if (nva=nil) then Exit;

 nva[i]:=nv;

 PcharTrim(nva[i].name ,nva[i].namelen);
 PcharTrim(nva[i].value,nva[i].valuelen);

 if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_NAME)=0 then
     nva[i].name :=CopyPchar(nva[i].name ,nva[i].namelen);

 if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_VALUE)=0 then
     nva[i].value:=CopyPchar(nva[i].value,nva[i].valuelen);

end;

Procedure Tnvp.insert_nocopy(name:PAnsiChar;namelen:size_t;value:PAnsiChar;valuelen:size_t); inline;
Var
 nv:Tnghttp2_nv;
begin
 nv:=Default(Tnghttp2_nv);
 nv.name    :=Pointer(name);
 nv.value   :=Pointer(value);
 nv.namelen :=namelen;
 nv.valuelen:=valuelen;
 nv.flags   :=NGHTTP2_NV_FLAG_NO_COPY_NAME or NGHTTP2_NV_FLAG_NO_COPY_VALUE;
 insert(nv);
end;

procedure Tnvp._set_value_nocopy(i:size_t;value:PAnsiChar;valuelen:size_t); inline;
begin
 if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_VALUE)=0 then
 begin
  FreeMem(nva[i].value);
  nva[i].flags:=nva[i].flags or NGHTTP2_NV_FLAG_NO_COPY_VALUE;
 end;
 nva[i].value   :=Pointer(value);
 nva[i].valuelen:=valuelen;
end;

procedure Tnvp._set_name_nocopy(i:size_t;name:PAnsiChar;namelen:size_t); inline;
begin
 if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_NAME)=0 then
 begin
  FreeMem(nva[i].name);
  nva[i].flags:=nva[i].flags or NGHTTP2_NV_FLAG_NO_COPY_NAME;
 end;
 nva[i].name   :=Pointer(name);
 nva[i].namelen:=namelen;
end;

Procedure Tnvp.copy(_nva:Pnghttp2_nv;_nvlen:size_t);
Var
 i:size_t;

begin
 if (_nva=nil) or (_nvlen=0) then Exit;
 clear;
 if (nva=nil) then
 begin
  nva:=AllocMem(_nvlen*SizeOf(Tnghttp2_nv));
 end else
 if (MemSize(nva)<_nvlen*SizeOf(Tnghttp2_nv)) then
 begin
  nva:=ReAllocMem(nva,_nvlen*SizeOf(Tnghttp2_nv));
 end;
 if (nva=nil) then Exit;
 Move(_nva^,nva^,_nvlen*SizeOf(Tnghttp2_nv));
 nvlen:=_nvlen;
 For i:=0 to nvlen-1 do
 begin
  PcharTrim(nva[i].name ,nva[i].namelen);
  PcharTrim(nva[i].value,nva[i].valuelen);

  if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_NAME)=0 then
      nva[i].name :=CopyPchar(nva[i].name ,nva[i].namelen);

  if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_VALUE)=0 then
      nva[i].value:=CopyPchar(nva[i].value,nva[i].valuelen);
 end;
end;

Procedure Tnvp.clear;
Var
 i:size_t;
begin
 if nvlen>0 then
 begin
  For i:=0 to nvlen-1 do
  begin
   if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_NAME)=0 then
      FreeMem(nva[i].name);
   if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_VALUE)=0 then
      FreeMem(nva[i].value);
  end;
  nvlen:=0;
  FillChar(nva^,nvlen*SizeOf(Tnghttp2_nv),0);
 end;
end;

function Tnvp.is_clear:Boolean; inline;
begin
 Result:=(nvlen=0) or (nva=nil);
end;

procedure Tfphttp1_stream.SetFlag(f:byte); inline;
begin
 flags:=flags or f;
end;

procedure Tfphttp1_stream.RetFlag(f:byte); inline;
begin
 flags:=flags and (not f);
end;

function  Tfphttp1_stream.GetFlag(f:byte):Boolean; inline;
begin
 Result:=flags and f<>0;
end;

procedure Tfphttp1_session.SetFlag(f:byte); inline;
begin
 FSettings.Fflags:=FSettings.Fflags or f;
end;

procedure Tfphttp1_session.RetFlag(f:byte); inline;
begin
 FSettings.Fflags:=FSettings.Fflags and (not f);
end;

function  Tfphttp1_session.GetFlag(f:byte):Boolean; inline;
begin
 Result:=FSettings.Fflags and f<>0;
end;

function Tfphttp1_stream.data_use:Boolean; inline;
begin
 Result:=FSend.data_prd.read_callback<>nil;
end;

function Tfphttp1_stream.is_live:Boolean; inline;
begin
 Result:=False;
 Case Fstate of
  NGHTTP2_STREAM_STATE_IDLE,
  NGHTTP2_STREAM_STATE_OPEN,
  NGHTTP2_STREAM_STATE_RESERVED_LOCAL,
  NGHTTP2_STREAM_STATE_RESERVED_REMOTE,
  NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL,
  NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE:Result:=True;
 end;
end;

function Tfphttp1_stream.is_half_close:Boolean; inline;
begin
 Result:=False;
 Case Fstate of
  NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL,
  NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE:Result:=True;
 end;
end;

function Tfphttp1_stream.is_reserved:Boolean; inline;
begin
 Result:=Fstate=0;
end;

function Tfphttp1_session._new_stream_id:int32; inline;
begin
 Case Fstreams.last_stream_id of
  High(int32),High(int32)-1:
  begin
   Exit(err_recv(NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE));
  end;
 end;
 Fstreams.last_stream_id:=Fstreams.last_stream_id+2;
 Result:=Fstreams.last_stream_id;
end;

function Tfphttp1_session._create_stream:Pfphttp1_stream;
Var
 id:int32;
begin
 Result:=nil;
 id:=_new_stream_id;
 if (id<0) then Exit;
 Result:=AllocMem(SizeOf(Tfphttp1_stream));
 if (Result=nil) then
 begin
  err_recv(NGHTTP2_ERR_NOMEM);
  Exit;
 end;
 Result^.Fstream_id:=id;
 Result^.Fstate:=NGHTTP2_STREAM_STATE_IDLE;
 Result^.Fparent:=@Fstreams.parent;
 Fstreams.Count:=Fstreams.Count+1;
 if Fstreams.parent.Fprev=nil then
 begin
  Fstreams.parent.Fprev:=Result;
  Fstreams.parent.Fnext:=Result;
  Fstreams.parent.Fparent:=Result;
 end else
 if GetFlag(fphttp1_server) then
 begin
  Result^.Fprev:=Fstreams.parent.Fnext;
  Fstreams.parent.Fnext^.Fnext:=Result;
  Fstreams.parent.Fnext:=Result;
  Fstreams.parent.Fparent:=Result;
 end else
 begin
  Result^.Fprev:=Fstreams.parent.Fparent;
  Fstreams.parent.Fparent^.Fnext:=Result;
  Fstreams.parent.Fparent:=Result;
 end;
end;

function Tfphttp1_session.step_next_stream:Boolean; inline;
begin
 Result:=false;
 if (Fstreams.parent.Fnext<>nil) then
  if (Fstreams.parent.Fnext^.Fnext<>nil) then
  begin
   Fstreams.parent.Fnext:=Fstreams.parent.Fnext^.Fnext;
   Result:=true;
  end;
end;

Procedure Tfphttp1_session._close_stream(is_recv:Boolean);
Var
 P:Pfphttp1_stream;
begin
 if Fstreams.Count>0 then
  Fstreams.Count:=Fstreams.Count-1;
 P:=Fstreams.parent.Fprev;
 if P=nil then Exit;
 P^.Fstate:=NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
 if _on_cb_stream_close(P,is_recv) then Exit;
 Fstreams.parent.Fprev:=P^.Fnext;
 if Fstreams.parent.Fprev=nil then
 begin
  Fstreams.parent.Fprev:=nil;
  Fstreams.parent.Fnext:=nil;
  Fstreams.parent.Fparent:=nil;
 end else
 begin
  Fstreams.parent.Fprev^.Fprev:=nil;
 end;
 P^.nvp.free;
 FreeMem(P);
end;

function Tfphttp1_session._reserved_stream:boolean; inline;
begin
 Result:=Fstreams.parent.Fprev<>nil;
 if Result then
  Result:=Fstreams.parent.Fprev^.is_reserved;
end;

function Tfphttp1_session.resume_stream:Pfphttp1_stream;
Var
 id:int32;
begin
 if _reserved_stream then
 begin
  Result:=nil;
  id:=_new_stream_id;
  if (id<0) then Exit;
  Result:=Fstreams.parent.Fprev;
  Result^.Fstream_id:=id;
  Result^.Fstate:=NGHTTP2_STREAM_STATE_IDLE;
  Fstreams.Count:=Fstreams.Count+1;
 end else
  Result:=_create_stream;
end;

function Tfphttp1_session.pending_stream:boolean; inline;
begin
 Result:=Fstreams.parent.Fprev<>nil;
 if Result then
  Result:=not Fstreams.parent.Fprev^.is_reserved;
end;

function Tfphttp1_session._closed_streams:Boolean; inline;
begin
 Result:=not (f_no_closed_streams in FSettings.nf);
end;

procedure  Tfphttp1_session.drop_stream(is_recv:Boolean);
Var
 P:Pfphttp1_stream;
begin
 P:=Fstreams.parent.Fprev;
 if (not _closed_streams) and
    (Fstreams.Count=1)    and
    (P<>nil) then
 begin
  P^.Fstate:=NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
  if _on_cb_stream_close(P,is_recv) then Exit;
  P^.Clear;
  P^.Fstate:=NGHTTP2_STREAM_STATE_CLOSED;
  if Fstreams.Count>0 then
   Fstreams.Count:=Fstreams.Count-1;
 end else
 begin
  _close_stream(is_recv);
 end;
end;

function Tfphttp1_session._on_cb_stream_close(P:Pfphttp1_stream;is_recv:Boolean):Boolean; inline;
begin
 Result:=False;
 if Assigned(Fcallbacks.Fon_stream_close_callback) and Assigned(P) then
 begin
  Case is_recv of
   True :Result:=_on_cb_err_fail_recv(Fcallbacks.Fon_stream_close_callback(@self,P^.Fstream_id,0,Fuser_data));
   False:Result:=_on_cb_err_fail_send(Fcallbacks.Fon_stream_close_callback(@self,P^.Fstream_id,0,Fuser_data));
  end;
 end;
end;

Procedure Tfphttp1_session.close_all_streams(todel,is_recv:Boolean); inline;
begin
 While (Fstreams.parent.Fprev<>nil) do
 begin
  if (not todel) and (Fstreams.parent.Fprev^.is_reserved) then Exit;
  _close_stream(is_recv);
 end;
end;

Procedure Tfphttp1_session._terminate; inline;
begin
 FHeaders.last_error:=NGHTTP2_ERR_SESSION_CLOSING;
 FSend.last_error   :=NGHTTP2_ERR_SESSION_CLOSING;
end;

function _on_nva_config_name(data:Pointer;len:SizeUInt):SizeInt; inline;
begin
 Result:=-1;
 if (data=nil) then Exit;
 Case len of
  7:Case (PQWord(Data)^ and $FFFFFFFFFFFFFF) or $20202020202000 of
     $656D656863733A:Result:=0; //:scheme
    end;
  8:Case PQWord(Data)^ or $2020202020202000 of
     $6E6F69737265763A:Result:=1; //:version
    end;
 end;
end;

function _on_http_version(data:Pointer;len:SizeUInt):SizeInt; forward;

Procedure Tfphttp1_session.nva_config(nva:Pnghttp2_nv;nvlen:size_t);
Var
 i:size_t;

begin
 if (nva=nil) or (nvlen=0) then Exit;
 For i:=0 to nvlen-1 do
 begin
  case _on_nva_config_name(nva[i].name,nva[i].namelen) of
   0://NGHTTP2_scheme:
   begin

    if Assigned(FSettings.scheme.FStr) then
    begin
     if not (f_no_free_scheme in FSettings.nf) then
     begin
      FSettings.scheme.Free;
     end;
     FSettings.scheme:=Default(TStrVal);
    end;
    FSettings.nf:=FSettings.nf-[f_no_free_scheme];

    if (nva[i].flags and NGHTTP2_NV_FLAG_NO_COPY_VALUE)=0 then
    begin
     FSettings.nf:=FSettings.nf+[f_no_free_scheme];
     FSettings.scheme:=TStrVal.New(nva[i].value,nva[i].valuelen);
     FSettings.scheme.TrimRight;
     FSettings.scheme.TrimLeftUnSafe;
    end else
    begin
     FSettings.scheme.CopyTrim(nva[i].value,nva[i].valuelen);
    end;

   end;
   1://fphttp1_version:
     __set_version(_on_http_version(nva[i].value,nva[i].valuelen));
  end;
 end;
end;

function  fphttp1_session_get_stream_user_data(session:Pnghttp2_session;stream_id:int32):pointer;cdecl;
Var
 P:Pfphttp1_stream;
begin
 Result:=nil;
 P:=Pointer(fphttp1_session_find_stream(session,stream_id));
 if P<>nil then
 begin
  Result:=P^.Fuser_data;
 end;
end;

function  fphttp1_session_set_stream_user_data(session:Pnghttp2_session;stream_id:int32;stream_user_data:pointer):cint;cdecl;
Var
 P:Pfphttp1_stream;
begin
 Result:=0;
 P:=Pointer(fphttp1_session_find_stream(session,stream_id));
 if P<>nil then
 begin
  P^.Fuser_data:=stream_user_data;
 end else
  Result:=NGHTTP2_ERR_INVALID_ARGUMENT;
end;

procedure fphttp1_session_set_user_data(session:Pnghttp2_session;user_data:pointer);cdecl;
begin
 if (session<>nil) then
  Pfphttp1_session(session)^.Fuser_data:=user_data;
end;

function  fphttp1_session_find_stream(session:Pnghttp2_session;stream_id:int32):Pnghttp2_stream;cdecl;
Var
 P:Pfphttp1_stream;
begin
 Result:=nil;
 if (session<>nil) then
  With Pfphttp1_session(session)^ do
  begin
   if stream_id=0 then
   begin
    Result:=@Fstreams.parent;
   end else
   if pending_stream then
   begin
    P:=Fstreams.parent.Fprev;
    While P<>nil do
    begin
     if P^.Fstream_id=stream_id then
     begin
      Result:=Pointer(P);
      Exit;
     end;
     P:=P^.Fnext;
    end;
   end;
  end;
end;

function  fphttp1_stream_get_state(stream:Pnghttp2_stream):Tnghttp2_stream_proto_state;cdecl;
begin
 Result:=NGHTTP2_STREAM_STATE_CLOSED;
 if stream<>nil then
 With Pfphttp1_stream(stream)^ do
 begin
  if is_live then
   Result:=Fstate;
 end;
end;

function  fphttp1_stream_get_stream_id(stream:Pnghttp2_stream):int32;cdecl;
begin
 Result:=0;
 if stream<>nil then
  Result:=Pfphttp1_stream(stream)^.Fstream_id;
end;

function  fphttp1_session_get_root_stream(session:Pnghttp2_session):Pnghttp2_stream;cdecl;
begin
 Result:=nil;
 if (session<>nil) then
  With Pfphttp1_session(session)^ do
  begin
   Result:=@Fstreams.parent;
  end;
end;

function  fphttp1_stream_get_parent(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;
begin
 Result:=nil;
 if stream<>nil then
  With Pfphttp1_stream(stream)^ do
   if Fstream_id<>0 then
    Result:=Pnghttp2_stream(Fparent);
end;

function  fphttp1_stream_get_next_sibling(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;
begin
 Result:=nil;
 if stream<>nil then
  With Pfphttp1_stream(stream)^ do
   if Fstream_id<>0 then
    Result:=Pnghttp2_stream(Fnext);
end;

function  fphttp1_stream_get_previous_sibling(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;
begin
 Result:=nil;
 if stream<>nil then
  With Pfphttp1_stream(stream)^ do
   if Fstream_id<>0 then
    Result:=Pnghttp2_stream(Fprev);
end;

function  fphttp1_stream_get_first_child(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl;
begin
 Result:=nil;
 if stream<>nil then
  With Pfphttp1_stream(stream)^ do
   if Fstream_id=0 then
    Result:=Pnghttp2_stream(Fprev);
end;

function  fphttp1_session_check_server_session(session:Pnghttp2_session):cint;cdecl;
begin
 Result:=0;
 if session<>nil then
  if Pfphttp1_session(session)^.GetFlag(fphttp1_server) then
   Result:=1;
end;

function Tfphttp1_session.err_recv(err:ssize_t):ssize_t; inline;
begin
 FHeaders.last_error:=err;
 Result:=err;
end;

function Tfphttp1_session.err_send(err:ssize_t):ssize_t; inline;
begin
 FSend.last_error:=err;
 Result:=err;
end;

function Tfphttp1_session._on_cb_error_recv(err:ssize_t):Boolean;
begin
 Result:=False;
 Case err of
  NGHTTP2_ERR_PAUSE:Result:=True;
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:
  begin
   FHeaders.last_error:=err;
  end;
  else
   if err<0 then
   begin
    FHeaders.last_error:=NGHTTP2_ERR_CALLBACK_FAILURE;
   end;
 end;
end;

function Tfphttp1_session._on_cb_error_before_send(err:ssize_t):Boolean;
begin
 Result:=False;
 Case err of
  NGHTTP2_ERR_CANCEL:Result:=True;
  else
   if err<0 then
   begin
    FSend.last_error:=NGHTTP2_ERR_CALLBACK_FAILURE;
   end;
 end;
end;

function Tfphttp1_session._on_cb_err_fail_send(err:ssize_t):Boolean; inline;
begin
 Result:=err<0;
 if Result then
 begin
  FSend.last_error:=NGHTTP2_ERR_CALLBACK_FAILURE;
 end;
end;

function Tfphttp1_session._on_cb_err_fail_recv(err:ssize_t):Boolean; inline;
begin
 Result:=err<0;
 if Result then
 begin
  FHeaders.last_error:=NGHTTP2_ERR_CALLBACK_FAILURE;
 end;
end;

function Tfphttp1_session._on_header_frame_recv(cat:Tnghttp2_headers_category;flags:uint8;stream_id:int32):Boolean;
Var
 frame:Tnghttp2_headers;
begin
 Result:=False;
 if Assigned(Fcallbacks.Fon_frame_recv_callback) then
 begin
  frame.hd.length   :=FHeaders.FrameSize;
  frame.hd.stream_id:=stream_id;
  frame.hd._type    :=NGHTTP2_HEADERS;
  frame.hd.flags    :=flags;
  frame.hd.reserved :=0;
  frame.padlen      :=0;
  frame.pri_spec.stream_id:=0;
  frame.pri_spec.weight   :=NGHTTP2_DEFAULT_WEIGHT;
  frame.pri_spec.exclusive:=0;

  frame.nva   :=nil;
  frame.nvlen :=0;
  frame.cat   :=cat;
  Result:=_on_cb_err_fail_recv(Fcallbacks.Fon_frame_recv_callback(@self,@frame,Fuser_data));
 end;
end;

function Tfphttp1_session._on_data_frame_recv(flags:uint8;stream_id:int32;len:size_t):Boolean;
Var
 frame:Tnghttp2_data;
begin
 Result:=false;
 if Assigned(Fcallbacks.Fon_frame_recv_callback) then
 begin
  frame.hd.length   :=len;
  frame.hd.stream_id:=stream_id;
  frame.hd._type    :=NGHTTP2_DATA;
  frame.hd.flags    :=flags;
  frame.hd.reserved :=0;
  frame.padlen      :=0;

  Result:=_on_cb_err_fail_recv(Fcallbacks.Fon_frame_recv_callback(@self,@frame,Fuser_data));
 end;
end;

function Tfphttp1_session._on_begin_header_frame(cat:Tnghttp2_headers_category;flags:uint8;stream_id:int32):Boolean;
Var
 frame:Tnghttp2_headers;
begin
 Result:=false;
 if Assigned(Fcallbacks.Fon_begin_frame_callback) or Assigned(Fcallbacks.Fon_begin_headers_callback) then
 begin
  frame.hd.length   :=0;
  frame.hd.stream_id:=stream_id;
  frame.hd._type    :=NGHTTP2_HEADERS;
  frame.hd.flags    :=flags;
  frame.hd.reserved :=0;
  frame.padlen      :=0;
  frame.pri_spec.stream_id:=0;
  frame.pri_spec.weight   :=NGHTTP2_DEFAULT_WEIGHT;
  frame.pri_spec.exclusive:=0;

  frame.nva   :=nil;
  frame.nvlen :=0;
  frame.cat   :=cat;
  if Assigned(Fcallbacks.Fon_begin_frame_callback) then
   Result:=_on_cb_err_fail_recv(Fcallbacks.Fon_begin_frame_callback(@self,@frame,Fuser_data));
  if (not Result) and Assigned(Fcallbacks.Fon_begin_headers_callback) then
   Result:=_on_cb_error_recv(Fcallbacks.Fon_begin_headers_callback(@self,@frame,Fuser_data));
 end;
end;

function Tfphttp1_session._on_begin_data_frame(flags:uint8;stream_id:int32;len:size_t):Boolean;
Var
 frame:Tnghttp2_data;
begin
 Result:=false;
 if Assigned(Fcallbacks.Fon_begin_frame_callback) then
 begin
  frame.hd.length   :=len;
  frame.hd.stream_id:=stream_id;
  frame.hd._type    :=NGHTTP2_DATA;
  frame.hd.flags    :=flags;
  frame.hd.reserved :=0;
  frame.padlen      :=0;

  Result:=_on_cb_err_fail_recv(Fcallbacks.Fon_begin_frame_callback(@self,@frame,Fuser_data));
 end;
end;

function Tfphttp1_session._on_header(cat:Tnghttp2_headers_category;stream_id:int32;N,V:TStrVal):Boolean;
Var
 frame:Tnghttp2_headers;
begin
 Result:=False;
 if Assigned(Fcallbacks.Fon_header_callback) then
 begin
  frame.hd.length   :=FHeaders.FrameSize;
  frame.hd.stream_id:=stream_id;
  frame.hd._type    :=NGHTTP2_HEADERS;
  frame.hd.flags    :=NGHTTP2_FLAG_END_HEADERS;
  frame.hd.reserved :=0;
  frame.padlen      :=0;
  frame.pri_spec.stream_id:=0;
  frame.pri_spec.weight   :=NGHTTP2_DEFAULT_WEIGHT;
  frame.pri_spec.exclusive:=0;

  frame.nva   :=nil;
  frame.nvlen :=0;
  frame.cat   :=cat;
  Result:=_on_cb_error_recv(Fcallbacks.Fon_header_callback(@self,@frame,
                            Pointer(N.FStr),N.FLen,
                            Pointer(V.FStr),V.FLen,
                            0,Fuser_data));
 end;
end;

function Tfphttp1_session._on_invalid_header(cat:Tnghttp2_headers_category;stream_id:int32;N,V:TStrVal):Boolean;
Var
 frame:Tnghttp2_headers;
begin
 Result:=False;
 if Assigned(Fcallbacks.Fon_invalid_header_callback) then
 begin
  frame.hd.length   :=FHeaders.FrameSize;
  frame.hd.stream_id:=stream_id;
  frame.hd._type    :=NGHTTP2_HEADERS;
  frame.hd.flags    :=NGHTTP2_FLAG_END_HEADERS;
  frame.hd.reserved :=0;
  frame.padlen      :=0;
  frame.pri_spec.stream_id:=0;
  frame.pri_spec.weight   :=NGHTTP2_DEFAULT_WEIGHT;
  frame.pri_spec.exclusive:=0;

  frame.nva   :=nil;
  frame.nvlen :=0;
  frame.cat   :=cat;
  Result:=_on_cb_error_recv(Fcallbacks.Fon_invalid_header_callback(@self,@frame,
                            Pointer(N.FStr),N.FLen,
                            Pointer(V.FStr),V.FLen,
                            0,Fuser_data));
 end;
end;

function Tfphttp1_session._on_data_chunk_recv(flags:uint8;stream_id:int32;data:Pointer;len:size_t):Boolean; inline;
begin
 Result:=False;
 if Assigned(Fcallbacks.Fon_data_chunk_recv_callback) then
 begin
  Result:=_on_cb_error_recv(Fcallbacks.Fon_data_chunk_recv_callback(
                            @self,flags,
                            stream_id,
                            data,len,
                            Fuser_data));
 end;
end;

function Tfphttp1_session._on_before_frame_send(cat:Tnghttp2_headers_category;P:Pfphttp1_stream):Boolean;
Var
 frame:Tnghttp2_headers;
begin
 Result:=False;
 if Assigned(Fcallbacks.Fbefore_frame_send_callback) then
 begin
  frame.hd.length   :=0;
  frame.hd.stream_id:=P^.Fstream_id;
  frame.hd._type    :=NGHTTP2_HEADERS;
  frame.hd.flags    :=NGHTTP2_FLAG_END_HEADERS;
  frame.hd.reserved :=0;
  frame.padlen      :=0;
  frame.pri_spec.stream_id:=0;
  frame.pri_spec.weight   :=NGHTTP2_DEFAULT_WEIGHT;
  frame.pri_spec.exclusive:=0;

  frame.nva   :=P^.nvp.nva;
  frame.nvlen :=P^.nvp.nvlen;
  frame.cat   :=cat;
  Result:=_on_cb_error_before_send(Fcallbacks.Fbefore_frame_send_callback(@self,@frame,Fuser_data));
 end;
end;

function Tfphttp1_session._on_header_frame_send(cat:Tnghttp2_headers_category;P:Pfphttp1_stream;len:size_t):Boolean;
Var
 frame:Tnghttp2_headers;
begin
 Result:=false;
 if Assigned(Fcallbacks.Fon_frame_send_callback) then
 begin
  frame.hd.length   :=len;
  frame.hd.stream_id:=P^.Fstream_id;
  frame.hd._type    :=NGHTTP2_HEADERS;
  frame.hd.flags    :=NGHTTP2_FLAG_END_HEADERS;
  frame.hd.reserved :=0;
  frame.padlen      :=0;
  frame.pri_spec.stream_id:=0;
  frame.pri_spec.weight   :=NGHTTP2_DEFAULT_WEIGHT;
  frame.pri_spec.exclusive:=0;

  frame.nva   :=P^.nvp.nva;
  frame.nvlen :=P^.nvp.nvlen;
  frame.cat   :=cat;
  Result:=_on_cb_err_fail_send(Fcallbacks.Fon_frame_send_callback(@self,@frame,Fuser_data));
 end;
end;

function Tfphttp1_session._on_data_frame_send(stream_id:int32;len:size_t):Boolean;
Var
 frame:Tnghttp2_data;
begin
 Result:=false;
 if Assigned(Fcallbacks.Fon_frame_send_callback) then
 begin
  frame.hd.length   :=len;
  frame.hd.stream_id:=stream_id;
  frame.hd._type    :=NGHTTP2_DATA;
  frame.hd.flags    :=NGHTTP2_FLAG_END_STREAM;
  frame.hd.reserved :=0;
  frame.padlen      :=0;

  Result:=_on_cb_err_fail_send(Fcallbacks.Fon_frame_send_callback(@self,@frame,Fuser_data));
 end;
end;

function Tfphttp1_session._on_header_frame_not_send(cat:Tnghttp2_headers_category;P:Pfphttp1_stream):Boolean;
Var
 frame:Tnghttp2_headers;
begin
 Result:=false;
 if Assigned(Fcallbacks.Fon_frame_not_send_callback) then
 begin
  frame.hd.length   :=0;
  frame.hd.stream_id:=P^.Fstream_id;
  frame.hd._type    :=NGHTTP2_HEADERS;
  frame.hd.flags    :=NGHTTP2_FLAG_END_HEADERS;
  frame.hd.reserved :=0;
  frame.padlen      :=0;
  frame.pri_spec.stream_id:=0;
  frame.pri_spec.weight   :=NGHTTP2_DEFAULT_WEIGHT;
  frame.pri_spec.exclusive:=0;

  frame.nva   :=P^.nvp.nva;
  frame.nvlen :=P^.nvp.nvlen;
  frame.cat   :=cat;
  Result:=_on_cb_err_fail_send(Fcallbacks.Fon_frame_not_send_callback(@self,@frame,FSend.last_error,Fuser_data));
 end;
end;

function Tfphttp1_session._on_send_data_nocopy(P:Pfphttp1_stream;len:size_t;src:Pnghttp2_data_source;data_flags:uint8):ssize_t; inline;
Var
 frame:Tnghttp2_data;
begin
 Result:=NGHTTP2_ERR_CALLBACK_FAILURE;
 if Assigned(Fcallbacks.Fsend_data_callback) then
 begin
  frame.hd.length   :=len;
  frame.hd.stream_id:=P^.Fstream_id;
  frame.hd._type    :=NGHTTP2_DATA;
  frame.hd.flags    :=data_flags;
  frame.hd.reserved :=0;
  frame.padlen      :=0;

  Result:=Fcallbacks.Fsend_data_callback(@self,@frame,Pointer(P),len,src,Fuser_data);
 end;
end;

function Tfphttp1_session._on_get_data_source_read_length:ssize_t; inline;
begin
 Result:=Def_block_len;
 if Assigned(Fcallbacks.Fsource_read_length_callback) then
 begin
  Result:=Fcallbacks.Fsource_read_length_callback(@Self,NGHTTP2_DATA,Fstreams.last_stream_id,
                Def_block_len,Def_block_len,Def_block_len,Fuser_data);
  if Result>Def_block_len then Result:=Def_block_len;
  if Result<0 then Result:=0;
 end;
end;

function Tfphttp1_session._no_client_magic:Boolean   inline;
begin
 Result:=(f_no_client_magic in FSettings.nf);
end;

Procedure Tfphttp1_session._err_http_messaging; inline;
begin
 if (f_no_http_messaging in FSettings.nf) then
  FHeaders.last_error:=NGHTTP2_ERR_HTTP_MESSAGING;
end;

Procedure Tfphttp1_session._set_KeepAlive(A:Boolean); inline;
begin
 Case A of
  True :SetFlag(fphttp1_alive);
  False:RetFlag(fphttp1_alive);
 end;
end;

Procedure Tfphttp1_session.__set_version(V:Byte); inline;
begin
 Case V of
   0,
   9,
   10:begin
       FSettings.Version:=10;
       _set_KeepAlive(False);
      end;
  11:begin
      FSettings.Version:=11;
      _set_KeepAlive(True);
     end;
 end;
end;

Procedure Tfphttp1_session._set_version(V:Byte;strong:Boolean);
begin
 Case strong of
  True :strong:=(FSettings.Version=0);
  False:strong:=(FSettings.Version<>9) or (V=9);
 end;
 if strong then
 begin
  Case V of
    9:begin
       FSettings.Version:=9;
       _set_KeepAlive(False);
      end;
   10:begin
       FSettings.Version:=10;
       _set_KeepAlive(False);
      end;
   11:begin
       FSettings.Version:=11;
       _set_KeepAlive(True);
      end;
   else
      FHeaders.last_error:=NGHTTP2_ERR_UNSUPPORTED_VERSION;
  end;
 end else
 if (FSettings.Version<>V) then
 begin
  FHeaders.last_error:=NGHTTP2_ERR_PROTO;
 end;
end;

Procedure Tfphttp1_session._on_field_name; inline;
begin
 FHeaders.Count:=FHeaders.Count+1;
 if FHeaders.Count>=FSettings.MAX_HEADER_LIST_SIZE then
 begin
  err_recv(NGHTTP2_ERR_HTTP_HEADER);
 end;
 FHeaders.LastName.TrimRight;
 FHeaders.LastName.LowerCase;
end;

Procedure Tfphttp1_session._on_field_content_length; inline;
begin
 if GetFlag(fContentLen) or GetFlag(fTransfer) then
 begin
  _err_http_messaging;
 end else
 begin
  SetFlag(fContentLen);
 end;
 if FHeaders.last_error>=0 then
  if not FHeaders.LastValue.TryToInt_pos(FHeaders.DataSize) then
  begin
   _err_http_messaging;
  end;
end;

Procedure Tfphttp1_session._on_field_cookie(cat:Tnghttp2_headers_category;stream_id:int32); inline;
Var
 T:TStrVal;
 i:SizeInt;

 function _on_send_cb(V:TStrVal):Boolean; inline;
 begin
  Result:=true;
  V.TrimLeftUnSafe;
  V.TrimRight;
  if (V.FLen<>0) then
  begin
   V.SetZeroChar;
   Result:=_on_header(cat,stream_id,FHeaders.LastName,V)
  end;
 end;

begin
 T:=FHeaders.LastValue;
 repeat
  i:=System.IndexByte(T.FStr^,T.FLen,Byte(';'));

  if (i=-1) then
  begin
   _on_send_cb(T);
   FHeaders.LastName .Reset;
   FHeaders.LastValue.Reset;
   Exit;
  end;

  if _on_send_cb(TStrVal.New(T.FStr,i)) then Exit;
  T.FStr:=@T.FStr[i+1];
  T.FLen:=T.FLen-i-1;

 until false;
end;

function _field_cb_name(data:Pointer;len:SizeUInt):SizeInt;
begin
 Result:=-1;
 if (data=nil) then Exit;
 Case len of
  4:Case PDWord(Data)^ or $20202020 of
     $74736F68:Result:=0; //host
    end;
  5:Case PDWord(Data)^ or $20202000 of
     $7461703A: //:pat
               Case PByte(Data)[4]  or $20 of
                $68:Result:=8; //h
               end;
    end;
  6:Case PDWord(Data)^ or $20202020 of
     $6B6F6F63: //cook
               Case PWord(Data)[2] or $2020 of
                $6569:Result:=2; //ie
               end;
     $65707865: //expe
               Case PWord(Data)[2] or $2020 of
                $7463:Result:=5; //ct
               end;
    end;
  7:Case (PQWord(Data)^ and $FFFFFFFFFFFFFF) or $20202020202000 of
     $646F6874656D3A:Result:=7;  //:method
     $656D656863733A:Result:=9;  //:scheme
     $7375746174733A:Result:=10; //:status
    end;
  10:Case PQWord(Data)^ or $2020202020202000 of
      $69726F687475613A: //:authori
                        Case PWord(Data)[4] or $2020 of
                         $7974:Result:=6; //ty
                        end;
      $697463656E6E6F43, //Connecti
      $697463656E6E6F63: //connecti
                        Case PWord(Data)[4] or $2020 of
                         $6E6F:Result:=3; //on
                        end;
     end;
  14:Case PQWord(Data)^ or $0020202020202020 of
      $2D746E65746E6F63: //content-
                        Case PDWord(Data)[2] or $20202020 of
                         $676E656C: //leng
                                   Case PWord(Data)[6] or $2020 of
                                    $6874:Result:=1; //th
                                   end;
                        end;
     end;
  17:Case PQWord(Data)^ or $2020202020202020 of
      $726566736E617274: //transfer
                        Case PQWord(Data)[1] or $2020202020202000 of
                         $6E69646F636E652D: //-encodin
                                           Case PByte(Data)[16] or $20 of
                                            $67:Result:=4; //g
                                           end;
                        end;
     end;
 end;
end;

function _value_100_continue(data:Pointer;len:SizeUInt):Boolean; inline;
begin
 Result:=false;
 if (data=nil) then Exit;
 Case len of
  12:Case PQWord(Data)^ or $2020202000000000 of
      $746E6F632D303031: //100-cont
                        Case PDWord(Data)[2] or $20202020 of
                         $65756E69:Result:=true; //inue
                        end;
     end;
 end;
end;

function _on_keep_alive(data:Pointer;len:SizeUInt):SizeInt; inline;
begin
 Result:=-1;
 if (data=nil) then Exit;
 Case len of
  5:Case PDWord(Data)^ or $20202020 of
     $736F6C63: //clos
               Case PByte(Data)[4] or $20 of
                $65:Result:=1; //e
               end;
    end;
  10:Case PQWord(Data)^ or $2020200020202020 of
      $696C612D7065656B: //keep-ali
                        Case PWord(Data)[4] or $2020 of
                         $6576:Result:=0; //ve
                        end;
     end;
 end;
end;

function _parse_connection(data:Pointer;len:SizeUInt):SizeInt;
Var
 T:TStrVal;
 i:SizeInt;

 function _on_check(V:TStrVal):SizeInt; inline;
 begin
  V.TrimLeftUnSafe;
  V.TrimRight;
  Result:=_on_keep_alive(V.FStr,V.FLen);
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
  if Result<>-1 then Exit;
  T.FStr:=@T.FStr[i+1];
  T.FLen:=T.FLen-i-1;
 until false;
end;

function _on_tfe_value(data:Pointer;len:SizeUInt):SizeInt; inline;
begin
 Result:=-1;
 if (data=nil) then Exit;
 Case len of
  7:Case (PQWord(Data)^ and $FFFFFFFFFFFFFF) or $20202020202020 of
     $64656B6E756863:Result:=0; //chunked
    end;
 end;
end;

function _parse_tfe(data:Pointer;len:SizeUInt):SizeInt;
Var
 T:TStrVal;
 i:SizeInt;

 function _on_check(V:TStrVal):SizeInt; inline;
 begin
  V.TrimLeftUnSafe;
  V.TrimRight;
  Result:=_on_tfe_value(V.FStr,V.FLen);
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
  if Result<>-1 then Exit;
  T.FStr:=@T.FStr[i+1];
  T.FLen:=T.FLen-i-1;
 until false;
end;

Procedure Tfphttp1_session._on_field_request_cb_val(P:Pfphttp1_stream);
begin
 FHeaders.LastValue.TrimRight;

 if (FHeaders.LastName .FLen=0) or
    (FHeaders.LastValue.FLen=0) then
 begin
  _on_invalid_header(NGHTTP2_HCAT_REQUEST,P^.Fstream_id,
                     FHeaders.LastName,FHeaders.LastValue);
  Exit;
 end;

 Case _field_cb_name(FHeaders.LastName.FStr,FHeaders.LastName.FLen) of
  0: //host
  if GetFlag(fHost) then
  begin
   _err_http_messaging;
  end else
  begin
   SetFlag(fHost);
   FHeaders.LastValue.SetZeroChar;
   _on_header(NGHTTP2_HCAT_REQUEST,P^.Fstream_id,
     TStrVal.New(PChar(NGHTTP2_authority),Length(NGHTTP2_authority)),
     FHeaders.LastValue);
   FHeaders.LastName .Reset;
   FHeaders.LastValue.Reset;
   Exit;
  end;
  1:_on_field_content_length; //content-length
  2: //cookie
  begin
   _on_field_cookie(NGHTTP2_HCAT_REQUEST,P^.Fstream_id);
   Exit;
  end;
  3: //connection
  begin
   if GetFlag(fConnection) then
   begin
    _err_http_messaging;
   end else
   begin
    SetFlag(fConnection);
   end;
   if FHeaders.last_error>=0 then
   begin
    Case _parse_connection(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen) of
     1:P^.SetFlag(fphttp1_GOAWAY); //close
    end;
   end;
   FHeaders.LastName .Reset;
   FHeaders.LastValue.Reset;
   Exit;
  end;
  4: //transfer-encoding //encoding was send for client
  begin
   if GetFlag(fTransfer) or GetFlag(fContentLen) or (FSettings.Version<>11) then
   begin
    _err_http_messaging;
   end else
   begin
    SetFlag(fTransfer);
   end;
   if FHeaders.last_error>=0 then
   begin
    Case _parse_tfe(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen) of
     0:P^.SetFlag(fphttp1_RECV_CHUNK); //chunked
    end;
   end;
   FHeaders.LastName .SetZeroChar;
   FHeaders.LastValue.SetZeroChar;
   if _on_invalid_header(NGHTTP2_HCAT_REQUEST,P^.Fstream_id,
                         FHeaders.LastName,FHeaders.LastValue) then Exit;
   FHeaders.LastName .Reset;
   FHeaders.LastValue.Reset;
   Exit;
  end;
  5: //expect
  begin
   if GetFlag(fExpect) or (FSettings.Version<>11) then
   begin
    _err_http_messaging;
   end else
   begin
    SetFlag(fExpect);
   end;
   if _value_100_continue(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen) then
   begin
    P^.SetFlag(fphttp1_EXPECT); //
   end else
   begin
    err_recv(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
   end;
  end;
 end;

 FHeaders.LastName .SetZeroChar;
 FHeaders.LastValue.SetZeroChar;

 _on_header(NGHTTP2_HCAT_REQUEST,P^.Fstream_id,
            FHeaders.LastName,FHeaders.LastValue);

 FHeaders.LastName .Reset;
 FHeaders.LastValue.Reset;
end;

Procedure Tfphttp1_session._on_field_response_cb_val(cat:Tnghttp2_headers_category;P:Pfphttp1_stream);
begin
 FHeaders.LastValue.TrimRight;

 if (FHeaders.LastName .FLen=0) or
    (FHeaders.LastValue.FLen=0) then
 begin
  _on_invalid_header(cat,P^.Fstream_id,
                     FHeaders.LastName,FHeaders.LastValue);
  Exit;
 end;

 Case _field_cb_name(FHeaders.LastName.FStr,FHeaders.LastName.FLen) of
  1:_on_field_content_length; //content-length
  2: //cookie
  begin
   _on_field_cookie(cat,P^.Fstream_id);
   Exit;
  end;
  3: //connection
  begin
   if GetFlag(fConnection) then
   begin
    _err_http_messaging;
   end else
   begin
    SetFlag(fConnection);
   end;
   if FHeaders.last_error>=0 then
   begin
    Case _parse_connection(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen) of
     1:P^.SetFlag(fphttp1_GOAWAY); //close
    end;
   end;
   FHeaders.LastName .Reset;
   FHeaders.LastValue.Reset;
   Exit;
  end;
  4: //transfer-encoding //encoding was send for server
  begin
   if GetFlag(fTransfer) or GetFlag(fContentLen) or (FSettings.Version<>11) then
   begin
    _err_http_messaging;
   end else
   begin
    SetFlag(fTransfer);
   end;
   if FHeaders.last_error>=0 then
   begin
    Case _parse_tfe(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen) of
     0:P^.SetFlag(fphttp1_RECV_CHUNK); //chunked
    end;
   end;
   FHeaders.LastName .SetZeroChar;
   FHeaders.LastValue.SetZeroChar;
   if _on_invalid_header(cat,P^.Fstream_id,
                         FHeaders.LastName,FHeaders.LastValue) then Exit;
   FHeaders.LastName .Reset;
   FHeaders.LastValue.Reset;
   Exit;
  end;
 end;

 FHeaders.LastName .SetZeroChar;
 FHeaders.LastValue.SetZeroChar;

 _on_header(cat,P^.Fstream_id,
            FHeaders.LastName,FHeaders.LastValue);

 FHeaders.LastName .Reset;
 FHeaders.LastValue.Reset;
end;

Procedure Tfphttp1_session._on_version_cb_09(stream_id:int32);
begin
 _set_version(9,true);
 _on_header_cb_val(NGHTTP2_HCAT_REQUEST,stream_id,
                   NGHTTP2_path,Length(NGHTTP2_path));
 _on_invalid_header(NGHTTP2_HCAT_REQUEST,stream_id,
   TStrVal.New(PChar(fphttp1_version),Length(fphttp1_version)),
   TStrVal.New(PChar(fphttp1_http_0_9),Length(fphttp1_http_0_9)));
 FHeaders.LastName .Reset;
 FHeaders.LastValue.Reset;
end;

function _on_http_version(data:Pointer;len:SizeUInt):SizeInt; inline;
begin
 Result:=0;
 if (data=nil) then Exit;
 Case len of
  8:Case PQWord(Data)^ or $20202020 of
     $392E302F70747468:Result:=9;   //http/0.9
     $302E312F70747468:Result:=10;  //http/1.0
     $312E312F70747468:Result:=11;  //http/1.1
    end;
 end;
end;

function __on_http_version(data:Pointer;len:SizeUInt):SizeInt; inline;
begin
 Result:=_on_http_version(data,len);
 if Result=9 then Result:=0;
end;

Procedure Tfphttp1_session._on_version_cb_val(cat:Tnghttp2_headers_category;stream_id:int32;strong:Boolean);
begin

 FHeaders.LastValue.TrimRight;
 FHeaders.LastValue.LowerCase;
 FHeaders.LastValue.SetZeroChar;

 _set_version(__on_http_version(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen),strong);

 _on_invalid_header(cat,stream_id,
   TStrVal.New(PChar(fphttp1_version),Length(fphttp1_version)),
   FHeaders.LastValue);

 if FSettings.scheme.FLen<>0 then
 begin
  _on_header(cat,stream_id,
    TStrVal.New(PChar(NGHTTP2_scheme),Length(NGHTTP2_scheme)),
    FSettings.scheme);
 end;
 FHeaders.LastName .Reset;
 FHeaders.LastValue.Reset;
end;

Procedure Tfphttp1_session._on_header_cb_val(cat:Tnghttp2_headers_category;stream_id:int32;hname:PChar;len:SizeUint);
begin
 FHeaders.LastValue.TrimRight;
 FHeaders.LastValue.SetZeroChar;
 _on_header(cat,stream_id,TStrVal.New(hname,len),FHeaders.LastValue);
 FHeaders.LastName .Reset;
 FHeaders.LastValue.Reset;
end;

Procedure Tfphttp1_session._on_method_cb_val(P:Pfphttp1_stream); inline;
begin
 FHeaders.LastValue.TrimRight;

 if method_has_request_data(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen) then
 begin
  FHeaders.DataSize:=-1;
  P^.SetFlag(fphttp1_HAS_REQS_D);
 end;

 if method_has_response_data(FHeaders.LastValue.FStr,FHeaders.LastValue.FLen) then
 begin
  P^.SetFlag(fphttp1_HAS_RESP_D);
 end;

 _on_header_cb_val(NGHTTP2_HCAT_REQUEST,P^.Fstream_id,
                   NGHTTP2_method,Length(NGHTTP2_method));
end;

Procedure Tfphttp1_session._on_status_cb_val(stream_id:int32); inline;
begin
 FHeaders.LastValue.TrimRight;
 _on_header_cb_val(NGHTTP2_HCAT_RESPONSE,stream_id,
                   NGHTTP2_status,Length(NGHTTP2_status));
end;

{                         #13#10
0  1  2   3         4     5  6
  GET   /query   HTTP/1.1 CR LF
   7    8                 9  10 8
  HOST  :     value       CR LF SP
11 12
CR LF
}

{                         #13#10
0  1        2   3    4    5  6
  HTTP/1.1     200   OK   CR LF
   7    8                 9  10 8
  HOST  :     value       CR LF SP
11 12
CR LF
}

{

0  //nop
1  //begin
2  //method/version
3  //version 0.9/not message #10
4  //version 0.9/not message #13
5  //path/status
6  //version/message
7  //field name
8  //field value
9  //field value and add

}

function Tfphttp1_session._parse_char(Ch:AnsiChar):ssize_t;

 procedure setstate(s:ssize_t); inline;
 begin
  FHeaders.state:=s;
 end;

begin
 Result:=0;
 Case FHeaders.state of
  0:Case Ch of
     #9,#10,#13,' ',
     '(',')','<','>','@',
     ',',';',':','\','"',
     '/','[',']','?','=',
     '{','}':;
     else
     begin
      FHeaders.LastValue.Reset;
      FHeaders.LastValue.AddChar(Ch);
      setstate(1);
      Result:=1; //begin
     end;
    end;
  1:Case Ch of
     #10:begin
          setstate(6);
          //Result:=NGHTTP2_ERR_PROTO;
          Result:=2; //method/version
         end;
     #13:begin
          setstate(5);
          //Result:=NGHTTP2_ERR_PROTO;
          Result:=2; //method/version
         end;
     ' ':begin
          setstate(2);
          Result:=2; //method/version
         end;
     else
         FHeaders.LastValue.AddChar(Ch);
    end;
  2:Case Ch of
     #10:begin
          //setstate(6);
          Result:=NGHTTP2_ERR_PROTO;
         end;
     #13:begin
          //setstate(5);
          Result:=NGHTTP2_ERR_PROTO;
         end;
     ' ':Result:=NGHTTP2_ERR_PROTO;
     else
      begin
       setstate(3);
       FHeaders.LastValue.AddChar(Ch);
      end;
    end;
  3:Case Ch of
     #10:Result:=3;  //version 0.9/not message #10
     #13:Result:=4;  //version 0.9/not message #13
     ' ':begin
          setstate(4);
          Result:=5;  //path/status
         end;
     else
         FHeaders.LastValue.AddChar(Ch);
    end;
  4:Case Ch of
     #10:begin
          setstate(6);
          Result:=6;  //version/message
         end;
     #13:begin
          setstate(5);
          Result:=6;  //version/message
        end;
     else
         FHeaders.LastValue.AddCharTrimLeft(Ch);
    end;
  5:Case Ch of
     #10:setstate(6);
     #13:begin
          setstate(11);
          Result:=8;  //field value
         end;
     else
         begin
          setstate(7);
          FHeaders.LastName.AddChar(Ch);
         end;
    end;
  6:Case Ch of
     #10:begin
          setstate(12);
          Result:=8;  //field value
         end;
     #13:begin
          setstate(11);
          Result:=8;  //field value
         end;
     else
         begin
          setstate(7);
          FHeaders.LastName.AddChar(Ch);
         end;
    end;
  7:Case Ch of
     #10:setstate(6);
     #13:setstate(5);
     ':':begin
          setstate(8);
          Result:=7;  //field name
         end;
     else
         FHeaders.LastName.AddChar(Ch);
    end;
  8:Case Ch of
     #10:setstate(10);
     #13:setstate(9);
     else
         FHeaders.LastValue.AddCharTrimLeft(Ch);
    end;
  9:Case Ch of
     #10:setstate(10);
     #13:begin
          setstate(11);
          Result:=8;  //field value
         end;
     ' ':setstate(8);
     else
         begin
          setstate(7);
          Result:=9;  //field value and add
         end;
    end;
 10:Case Ch of
     #10:begin
          setstate(12);
          Result:=8;  //field value
         end;
     #13:begin
          setstate(11);
          Result:=8;  //field value
         end;
     ' ':setstate(8);
     else
         begin
          setstate(7);
          Result:=9;  //field value and add
         end;
    end;
 11:Case Ch of
     #10:setstate(12);
     else
         Result:=NGHTTP2_ERR_PROTO;
    end;

 end;
end;

function _recv_data_trim(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;      forward;                  forward;
function _recv_data_len(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;       forward;
function _recv_data_chunked(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;   forward;
function _recv_request_header(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t; forward;

function Tfphttp1_session._headers_end(P:Pfphttp1_stream):Integer; inline;
begin
 Result:=0;
 reset_parse;
 if P^.GetFlag(fphttp1_RECV_CHUNK) then
 begin
  if FHeaders.DataSize=0 then //request not enj data
  begin
   P^.RetFlag(fphttp1_RECV_CHUNK);
   //no data, new stream
   recv_cb:=nil;
   Result:=1;
  end else
  begin
   recv_cb:=@_recv_data_chunked;
   FHeaders.DataSize:=0; //init to parse chunked
   //data read chunked
   Result:=2;
  end;
 end else
 begin
  Case FHeaders.DataSize of
   -1:begin
       P^.SetFlag(fphttp1_GOAWAY);
       recv_cb:=@_recv_data_trim;
       //data read trim
       Result:=3;
      end;
    0:begin
       //no data, new stream
       recv_cb:=nil;
       Result:=1;
      end;
    else
     begin
      recv_cb:=@_recv_data_len;
      //data read
      Result:=3;
     end;
  end;
 end;
end;

function _recv_request_header(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;

 procedure setstate(s:ssize_t); inline;
 begin
  session^.FHeaders.state:=s;
 end;

Var
 i:size_t;

begin
 Result:=0;

 with session^ do
 begin

  i:=len;

  if (FHeaders.FrameSize+i)>=FSettings.MAX_FRAME_SIZE then
  begin
   i:=FSettings.MAX_FRAME_SIZE-FHeaders.FrameSize;
  end;

  While (i<>0) do
  begin
   //if FHeaders.last_error<0 then Exit(len-i);

   Case PChar(data)^ of
    #0..#8,#11,#12,#14..#31,#127:
    begin
     err_recv(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
     Exit(len-i);
    end;
   end;
    {                         #13#10
    0  1  2   3         4     5  6
      GET   /query   HTTP/1.1 CR LF
       7    8                 9  10 8
      HOST  :     value       CR LF SP
    11 12
    CR LF
    }

    Case _parse_char(PChar(data)^) of
     NGHTTP2_ERR_PROTO:
     begin
      err_recv(NGHTTP2_ERR_PROTO);
      Exit(len-i);
     end;
     1:begin  //begin
        FHeaders.DataSize:=0;
        P^.Fstate:=NGHTTP2_STREAM_STATE_OPEN;
        if _on_begin_header_frame(NGHTTP2_HCAT_REQUEST,NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id) then Exit(len-i);
       end;
     2:_on_method_cb_val(P); //method
     3:begin //version 0.9 #10
        setstate(12);
        _on_version_cb_09(P^.Fstream_id);
       end;
     4:begin //version 0.9 #13
        setstate(11);
        _on_version_cb_09(P^.Fstream_id);
       end;
     5:_on_header_cb_val(NGHTTP2_HCAT_REQUEST,P^.Fstream_id,NGHTTP2_path,Length(NGHTTP2_path));  //path
     6:_on_version_cb_val(NGHTTP2_HCAT_REQUEST,P^.Fstream_id,true);  //version
     7:_on_field_name;      //field name
     8:_on_field_request_cb_val(P);    //field value
     9:begin;               //field value and add
        _on_field_request_cb_val(P);
        FHeaders.LastName.AddChar(PChar(data)^);
       end;
    end;

    if FHeaders.last_error<0 then Exit(len-i);

    if FHeaders.state=12 then
    begin
     Dec(i);
     Result:=len-i;
     i:=_headers_end(P);

     Case i of
      1:if _on_header_frame_recv(NGHTTP2_HCAT_REQUEST,NGHTTP2_FLAG_END_STREAM or NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id) then Exit;
      2,
      3:if _on_header_frame_recv(NGHTTP2_HCAT_REQUEST,NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id) then Exit;
     end;

     if GetFlag(fphttp1_upgrade) then
     begin
      recv_cb:=@_recv_data_trim;
      P^.FSend.DataSize:=0;
      i:=3;
     end;

     if i=3 then
      _on_begin_data_frame(NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id,P^.FSend.DataSize);

     Exit;
    end;
   Dec(i);
   Inc(data);
  end;
  Result:=len-i;

  FHeaders.FrameSize:=FHeaders.FrameSize+Result;
  if FHeaders.FrameSize>=FSettings.MAX_FRAME_SIZE then
  begin
   err_recv(NGHTTP2_ERR_FRAME_SIZE_ERROR);
   Exit;
  end;

 end;
end;

function _recv_response_header(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;

 procedure setstate(s:ssize_t); inline;
 begin
  session^.FHeaders.state:=s;
 end;

Var
 i:size_t;
 cat:Tnghttp2_headers_category;

begin
 Result:=0;

 if P^.GetFlag(fphttp1_EXPECT) then
  cat:=NGHTTP2_HCAT_HEADERS
 else
  cat:=NGHTTP2_HCAT_RESPONSE;

 with session^ do
 begin

  i:=len;

  if (FHeaders.FrameSize+i)>=FSettings.MAX_FRAME_SIZE then
  begin
   i:=FSettings.MAX_FRAME_SIZE-FHeaders.FrameSize;
  end;

  While (i<>0) do
  begin
   if FHeaders.last_error<0 then Exit(len-i);

   Case PChar(data)^ of
    #0..#8,#11,#12,#14..#31,#127:
    begin
     err_recv(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
     Exit(len-i);
    end;
   end;

   {                          #13#10
   0  1        2   3    4      5  6
     HTTP/1.1     200   OK     CR LF
      7    8                 9  10 8
     HOST  :     value       CR LF SP
   11 12
   CR LF
   }

   Case _parse_char(PChar(data)^) of
    NGHTTP2_ERR_PROTO:
    begin
     err_recv(NGHTTP2_ERR_PROTO);
     Exit(len-i);
    end;
    1:begin  //begin
       if P^.GetFlag(fphttp1_HAS_RESP_D) and (not P^.GetFlag(fphttp1_EXPECT)) then
       begin
        FHeaders.DataSize:=-1;
       end else
       begin
        FHeaders.DataSize:=0;
       end;
       if _on_begin_header_frame(cat,NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id) then Exit(len-i);
      end;
    2:_on_version_cb_val(cat,P^.Fstream_id,false); //version
    3:begin
       _on_status_cb_val(P^.Fstream_id);  //status
       setstate(6); //not message #10
      end;
    4:begin
       _on_status_cb_val(P^.Fstream_id);  //status
       setstate(5); //not message #13
      end;
    5:_on_status_cb_val(P^.Fstream_id);  //status
    6:begin;  //message ignore
       FHeaders.LastValue.Reset;
      end;
    7:_on_field_name;      //field name
    8:_on_field_response_cb_val(cat,P); //field value
    9:begin;               //field value and add
       _on_field_response_cb_val(cat,P);
       FHeaders.LastName.AddChar(PChar(data)^);
      end;
   end;

   if FHeaders.last_error<0 then Exit(len-i);

   if FHeaders.state=12 then
   begin
    Dec(i);
    Result:=len-i;
    if P^.GetFlag(fphttp1_EXPECT) then
    begin
     reset_parse;
     P^.RetFlag(fphttp1_EXPECT);
     _on_header_frame_recv(cat,NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id);

     if GetFlag(fphttp1_upgrade) then
     begin
      recv_cb:=@_recv_data_trim;
      P^.FSend.DataSize:=0;
     end;

    end else
    begin
     i:=_headers_end(P);

     Case i of
      1:if _on_header_frame_recv(cat,NGHTTP2_FLAG_END_STREAM or NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id) then Exit;
      2,
      3:if _on_header_frame_recv(cat,NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id) then Exit;
     end;

     if GetFlag(fphttp1_upgrade) then
     begin
      recv_cb:=@_recv_data_trim;
      P^.FSend.DataSize:=0;
      i:=3;
     end;

     if i=3 then
      _on_begin_data_frame(NGHTTP2_FLAG_END_HEADERS,P^.Fstream_id,P^.FSend.DataSize);

    end;
    Exit;
   end;

   Dec(i);
   Inc(data);
  end;
  Result:=len-i;

  FHeaders.FrameSize:=FHeaders.FrameSize+Result;
  if FHeaders.FrameSize>=FSettings.MAX_FRAME_SIZE then
  begin
   err_recv(NGHTTP2_ERR_FRAME_SIZE_ERROR);
   Exit;
  end;

 end;

end;

function  _recv_data_trim(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;
begin
 Result:=0;
 With session^ do
 begin
  FHeaders.FrameSize:=FHeaders.FrameSize+len;
  if _on_data_chunk_recv(0,P^.Fstream_id,data,len) then Exit;
 end;
 Result:=len;
end;

function _recv_data_len(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;
Var
 d:int64;
 flags:uint8;
begin
 Result:=0;

 With session^ do
 begin
  d:=FHeaders.DataSize-FHeaders.FrameSize;
  if len<d then
  begin
   flags:=0;
   d:=len;
  end else
  begin
   flags:=NGHTTP2_FLAG_END_STREAM;
  end;

  if _on_data_chunk_recv(flags,P^.Fstream_id,data,size_t(d)) then Exit;

  FHeaders.FrameSize:=FHeaders.FrameSize+d;

  Result:=size_t(d);
  if FHeaders.FrameSize>=FHeaders.DataSize then
  begin
   //end data, new stream
   recv_cb:=nil;
   _on_data_frame_recv(NGHTTP2_FLAG_END_STREAM,P^.Fstream_id,FHeaders.DataSize);
  end;
 end;
end;

function _recv_data_chunked(session:Pfphttp1_session;P:Pfphttp1_stream;data:Pointer;len:size_t):ssize_t;
Var
 i:size_t;
 d:Int64;

 procedure setstate(s:ssize_t); inline;
 begin
  session^.FHeaders.state:=s;
 end;

 function _to_data:Boolean;
 begin
  Result:=False;
  With session^ do
  begin
   FHeaders.FrameSize:=0;
   //Writeln('chunk DataSize:',FHeaders.DataSize);
   if FHeaders.DataSize=0 then //is end
   begin
    FHeaders.FrameSize:=0;
    setstate(5);
    if _on_data_chunk_recv(NGHTTP2_FLAG_END_STREAM,P^.Fstream_id,nil,0) then Exit(true);
   end else //chunk of data
   begin
    FHeaders.FrameSize:=0;
    setstate(2);
    Dec(i);
    Inc(data);
    Result:=true;
    _on_begin_data_frame(0,P^.Fstream_id,size_t(FHeaders.DataSize));
   end;
  end;
 end;

 Procedure _data_end; inline;
 begin
  Dec(i);
  Inc(data);
  setstate(0);
  //end data, new stream
  With session^ do
  begin
   recv_cb:=nil;
   _on_data_frame_recv(NGHTTP2_FLAG_END_STREAM,P^.Fstream_id,0);
  end;
 end;

 procedure _on_chunk_ext; inline;
 begin
  session^.FHeaders.FrameSize:=0;
  setstate(7);
 end;

 Procedure err_invalid; inline;
 begin
  session^.err_recv(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
 end;


Const
 DifLo=Byte('a')-$A;
 DifHi=Byte('A')-$A;
begin
 Result:=0;

 {    | extra field = ';' key = value |
 0  0  7       1  2  2
   FF [; ext] CR LF
        2  3  4
   //data CR LF
 0    1  2  8        8  9   5  6
   0 CR LF [trailer CR LF] CR LF ///#13#10
 }

 i:=len;

 With session^ do
  While (i<>0) and (FHeaders.last_error>=0) do
  begin

   if FHeaders.state=2 then //is data
   begin

    d:=FHeaders.DataSize-FHeaders.FrameSize;
    if i<d then d:=i;

    if (d=0) then Exit(len-i);

    if _on_data_chunk_recv(0,P^.Fstream_id,data,size_t(d)) then Exit(len-i);

    FHeaders.FrameSize:=FHeaders.FrameSize+d;

    Dec(i ,d);
    Inc(data,d);

    if FHeaders.FrameSize>=FHeaders.DataSize then
    begin
     _on_data_frame_recv(0,P^.Fstream_id,size_t(FHeaders.DataSize));
     setstate(3);
     FHeaders.FrameSize:=0;
     FHeaders.DataSize:=0;
    end;

   end else
   begin
    While (i<>0) do
    begin
     if (FHeaders.last_error<0) then Exit(len-i);

     FHeaders.FrameSize:=FHeaders.FrameSize+1;

     Case FHeaders.state of
      0:begin
        if FHeaders.FrameSize>=19 then
        begin
         err_recv(NGHTTP2_ERR_FRAME_SIZE_ERROR);
         Exit(len-i);
        end;
       end;
      8,
      7:begin
        if FHeaders.FrameSize>=FSettings.MAX_FRAME_SIZE then
        begin
         err_recv(NGHTTP2_ERR_FRAME_SIZE_ERROR);
         Exit(len-i);
        end;
       end;
     end;

     Case FHeaders.state of
      0:Case PChar(data)^ of
         #13:setstate(1);
         #10:if _to_data then Break;
         '0'..'9':FHeaders.DataSize:=(FHeaders.DataSize shl 4) or (PByte(data)^ and $F);
         'a'..'f':FHeaders.DataSize:=(FHeaders.DataSize shl 4) or (PByte(data)^-DifLo);
         'A'..'F':FHeaders.DataSize:=(FHeaders.DataSize shl 4) or (PByte(data)^-DifHi);
         ';':_on_chunk_ext;
         else err_invalid;
        end;
      1:Case PChar(data)^ of
         #10:if _to_data then Break;
         else err_invalid;
        end;
      3:Case PChar(data)^ of
         #13:setstate(4);
         #10:setstate(0);
         else err_invalid;
        end;
      4:Case PChar(data)^ of
         #10:setstate(0);
         else err_invalid;
        end;
      5:Case PChar(data)^ of
         #13:setstate(6);
         #10:begin
              _data_end;
              Exit(len-i);
             end;
         #0..#8,#11,#12,#14..#31,#127:err_invalid;
         else setstate(8);
        end;
      6:Case PChar(data)^ of
         #10:begin
              _data_end;
              Exit(len-i);
             end;
         else err_invalid;
        end;
      7:Case PChar(data)^ of
         #13:setstate(1);
         #10:if _to_data then Break;
        end;
      8:Case PChar(data)^ of
         #13:setstate(9);
         #10:setstate(5);
         #0..#8,#11,#12,#14..#31,#127:err_invalid;
        end;
      9:Case PChar(data)^ of
         #10:setstate(5);
         else err_invalid;
        end;
     end;

     Dec(i);
     Inc(data);
    end;
   end;
  end;

 Result:=len-i;

end;

Procedure Tfphttp1_session.reset_headers; inline;
begin
 RetFlag(fparse_all);
 reset_parse;
end;

Procedure Tfphttp1_session.reset_parse; inline;
begin
 FHeaders.state:=0;
 FHeaders.FrameSize:=0;
 FHeaders.Count:=0;

 if _closed_streams then
 begin
  FHeaders.LastName .Free;
  FHeaders.LastValue.Free;
 end else
 begin
  FHeaders.LastName .Reset;
  FHeaders.LastValue.Reset;
 end;
end;

function  fphttp1_session_want_read(session:Pnghttp2_session):cint;cdecl;
begin
 Result:=0;
 if (session=nil) then Exit;
  With Pfphttp1_session(session)^ do
  begin
   if GetFlag(fphttp1_alive) and (FHeaders.last_error>=0) then Exit(1);
  end;
end;

function  fphttp1_session_want_write(session:Pnghttp2_session):cint;cdecl;
Var
 P:Pfphttp1_stream;
begin
 Result:=0;
 if (session=nil) then Exit;
  With Pfphttp1_session(session)^ do
  begin
   P:=Fstreams.parent.Fprev;
   if pending_stream and
      (FSend.last_error>=0) and
      (
       (not P^.nvp.is_clear) or
       (P^.is_live)
      ) then Exit(1);
  end;
end;

function fphttp1_session_mem_recv(session:Pnghttp2_session;_in:Puint8;inlen:size_t):ssize_t;cdecl;

Var
 P:Pfphttp1_stream;

 procedure check_client_magic; inline;
 Var
  m:ssize_t;
 begin
  With Pfphttp1_session(session)^ do
  if not _no_client_magic then
  begin
   m:=fphttp1_magic(_in,inlen);
   if m<0 then err_recv(m);
  end;
 end;

begin
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 Result:=0;
 if (_in=nil) or (inlen=0) then Exit;
 repeat
  With Pfphttp1_session(session)^ do
  begin
   if FHeaders.last_error<0 then Exit(FHeaders.last_error);
   if GetFlag(fphttp1_server) then //server side
   begin

    if Assigned(recv_cb) then
    begin
     P:=Fstreams.parent.Fnext;
     if (P=nil)             then Exit(err_recv(NGHTTP2_ERR_INTERNAL));
     if (not P^.is_live)    then Exit(err_recv(NGHTTP2_ERR_INTERNAL));
     Result:=Result+recv_cb(Pfphttp1_session(session),P,@_in[Result],inlen-Result);
     if FHeaders.last_error<0 then Exit(FHeaders.last_error);
     if Result>=ssize_t(inlen) then Break;
    end else
    begin
     //new stream

     if GetFlag(fphttp1_upgrade) then
     begin
      recv_cb:=nil;
      Exit;
     end;

     Case FSettings.Version of
       //0:; //detect after
       9,
      10:if (Fstreams.Count>=1) then Exit(NGHTTP2_ERR_REFUSED_STREAM);
      11:begin
          if GetFlag(fphttp1_alive) then
          begin
           if (Fstreams.Count>=FSettings.MAX_STREAMS) then Exit(NGHTTP2_ERR_REFUSED_STREAM);
          end else
          begin
           if (Fstreams.Count>=1) then Exit(NGHTTP2_ERR_REFUSED_STREAM);
          end;
         end;
     end;

     check_client_magic;
     if FHeaders.last_error<0 then Exit(FHeaders.last_error);
     resume_stream;
     reset_headers;
     if FHeaders.last_error<0 then Exit(FHeaders.last_error);
     recv_cb:=@_recv_request_header;
    end;
   end else
   begin //client side
    if pending_stream then
    begin
     P:=Fstreams.parent.Fprev;

     if Assigned(recv_cb) then
     begin
      if (P=nil)             then Exit(err_recv(NGHTTP2_ERR_INTERNAL));
      if (not P^.is_live)    then Exit(err_recv(NGHTTP2_ERR_INTERNAL));
      Result:=Result+recv_cb(Pfphttp1_session(session),P,@_in[Result],inlen-Result);
      if FHeaders.last_error<0 then Exit(FHeaders.last_error);

      if recv_cb=nil then
      begin
       if P^.GetFlag(fphttp1_GOAWAY) then
       begin
        _set_KeepAlive(False);
       end;
       _send_end_stream(true);
       if _check_terminate then Exit(FHeaders.last_error);
      end;

      if Result>=ssize_t(inlen) then Break;
     end else
     begin

      if GetFlag(fphttp1_upgrade) then
      begin
       recv_cb:=nil;
       Exit;
      end;

      //new stream
      if (P<>nil) and P^.is_half_close then
      begin
       reset_headers;
       recv_cb:=@_recv_response_header;
      end else
       Exit;
     end;

    end else
    begin //not exist opened streams
     if _check_terminate then Exit(FSend.last_error);
     Exit;
    end;

   end;

  end;
 until (Result>=ssize_t(inlen));
 Result:=ssize_t(inlen);
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

function Tnvp.render_response_headers(Data:PPointer;sp:ssize_t;Version:Byte):ssize_t;
Var
 i:ssize_t;

 procedure add(P:PChar;L:ssize_t); inline;
 begin
  _nvp_add(Data,Result,PByte(P),L);
 end;

 procedure add(P:PByte;L:ssize_t); inline;
 begin
  _nvp_add(Data,Result,P,L);
 end;

begin
 Result:=0;
 if is_clear then Exit;
 Case Version of
  10:add(fphttp1_http_1_0_A,Length(fphttp1_http_1_0_A));
  11:add(fphttp1_http_1_1_A,Length(fphttp1_http_1_1_A));
  else
   Exit;
 end;

 if (sp<>-1) then
 begin
  add(nva[sp].value ,nva[sp].valuelen);
 end;
 add(fphttp1_NL     ,Length(fphttp1_NL));

 For i:=0 to nvlen-1 do
  if (nva[i].name<>nil) and (nva[i].namelen<>0) then
  begin
   add(nva[i].name  ,nva[i].namelen);
   add(fphttp1_VR   ,Length(fphttp1_VR));
   add(nva[i].value ,nva[i].valuelen);
   add(fphttp1_NL   ,Length(fphttp1_NL));
  end;

 add(fphttp1_NL     ,Length(fphttp1_NL));

end;

function Tnvp.render_request_headers(Data:PPointer;mp,pp:ssize_t;Version:Byte):ssize_t;

const
 fphttp1_SP_http_1_0_NL=' HTTP/1.0'#13#10;
 fphttp1_SP_http_1_1_NL=' HTTP/1.1'#13#10;

Var
 i:ssize_t;

 procedure add(P:PChar;L:ssize_t); inline;
 begin
  _nvp_add(Data,Result,PByte(P),L);
 end;

 procedure add(P:PByte;L:ssize_t); inline;
 begin
  _nvp_add(Data,Result,P,L);
 end;

begin
 Result:=0;
 if is_clear then Exit;

 if (mp<>-1) then
 begin
  add(nva[mp].value ,nva[mp].valuelen);
  add(fphttp1_SP    ,Length(fphttp1_SP));
 end else
 begin
  add(fphttp1_GET_SP,Length(fphttp1_GET_SP));
 end;

 if (pp<>-1) then
 begin
  add(nva[pp].value ,nva[pp].valuelen);
 end else
 begin
  add(fphttp1_BS    ,Length(fphttp1_BS));
 end;

 Case Version of
   9:begin
      add(fphttp1_NL           ,Length(fphttp1_NL));
      Exit;
     end;
  10:add(fphttp1_SP_http_1_0_NL,Length(fphttp1_SP_http_1_0_NL));
  11:add(fphttp1_SP_http_1_1_NL,Length(fphttp1_SP_http_1_1_NL));
  else
   Exit;
 end;

 For i:=0 to nvlen-1 do
  if (nva[i].name<>nil) and (nva[i].namelen<>0) then
  begin
   add(nva[i].name  ,nva[i].namelen);
   add(fphttp1_VR   ,Length(fphttp1_VR));
   add(nva[i].value ,nva[i].valuelen);
   add(fphttp1_NL   ,Length(fphttp1_NL));
  end;

 add(fphttp1_NL     ,Length(fphttp1_NL));

 //
end;

function Tnvp.render_trailers(p:ssize_t;Data:PPointer):ssize_t;
var
 i:ssize_t;

 procedure add(P:PChar;L:ssize_t); inline;
 begin
  _nvp_add(Data,Result,PByte(P),L);
 end;

 procedure add(P:PByte;L:ssize_t); inline;
 begin
  _nvp_add(Data,Result,P,L);
 end;

begin
 Result:=p;
 if is_clear then Exit;
 For i:=0 to nvlen-1 do
  if (nva[i].name<>nil) and (nva[i].namelen<>0) then
  begin
   add(nva[i].name  ,nva[i].namelen);
   add(fphttp1_VR   ,Length(fphttp1_VR));
   add(nva[i].value ,nva[i].valuelen);
   add(fphttp1_NL   ,Length(fphttp1_NL));
  end;
end;

function _send_rst(session:Pfphttp1_session;P:Pfphttp1_stream;var data:Pointer):ssize_t;
var
 frame:Tnghttp2_rst_stream;
begin
 With session^ do
  if Assigned(Fcallbacks.Fbefore_frame_send_callback) or
     Assigned(Fcallbacks.Fon_frame_send_callback) then
  begin
   frame.hd.length   :=0;
   frame.hd.stream_id:=P^.Fstream_id;
   frame.hd._type    :=NGHTTP2_RST_STREAM;
   frame.hd.flags    :=0;
   frame.hd.reserved :=0;
   frame.error_code  :=NGHTTP2_CANCEL;
  end;

 With session^ do
  if Assigned(Fcallbacks.Fbefore_frame_send_callback) then
  if _on_cb_err_fail_send(Fcallbacks.Fbefore_frame_send_callback(Pointer(session),@frame,Fuser_data)) then
   begin
    Exit(FSend.last_error);
   end;

 Case session^.FSettings.Version of
  10:
  begin
   Result:=Length(fphttp1_RST_0);
   data:=PAnsiChar(fphttp1_RST_0);
  end;
  11:
  begin
   Result:=Length(fphttp1_RST_1);
   data:=PAnsiChar(fphttp1_RST_1);
  end;
  else
   begin
    Result:=0;
    data:=nil;
   end;
 end;

 With session^ do
  if Assigned(Fcallbacks.Fon_frame_send_callback) then
   if _on_cb_err_fail_send(Fcallbacks.Fon_frame_send_callback(Pointer(session),@frame,Fuser_data)) then
   begin
    Exit(FSend.last_error);
   end;

 session^.send_cb:=nil;
end;

function _field_100(data:Pointer;len:SizeUInt):Boolean; inline;
begin
 Result:=false;
 if (data=nil) then Exit;
 if len>=3 then
  Case PDWord(Data)^ and $FFFFFF of
   $303031,              //100
   $313031,              //101
   $323031:Result:=true; //102
  end;
end;

function _get_content_length(nv:Pnghttp2_nv;var DataSize:Int64):Boolean; inline;
Var
 F:TStrVal;
begin
 F:=TStrVal.New(nv^.value,nv^.valuelen);
 F.TrimLeftUnSafe;
 F.TrimRight;
 Result:=F.TryToInt_pos(DataSize);
end;

function __send_data_buf(session:Pfphttp1_session;P:Pfphttp1_stream;var data:Pointer):ssize_t; forward;

function _send_response_headers(session:Pfphttp1_session;P:Pfphttp1_stream;var data:Pointer):ssize_t;
Var
 i,lp,cp,sp:ssize_t;
 field_100:Boolean;

 Procedure _err_http_messaging; inline;
 begin
  With session^ do
   if (f_no_http_messaging in FSettings.nf) then
    FSend.last_error:=NGHTTP2_ERR_HTTP_MESSAGING;
 end;

begin
 Result:=0;

 if (P^.nvp.nvlen=0) then Exit;

 lp:=-1;
 cp:=-1;
 sp:=-1;
 field_100:=false;

 With session^ do
 begin
  P^.FSend.DataSize:=-1;

  if not P^.nvp.is_clear then
   For i:=0 to P^.nvp.nvlen-1 do
   begin
    Case _field_cb_name(P^.nvp.nva[i].name,P^.nvp.nva[i].namelen) of
     1://NGHTTP2_content_length:
       begin
        if (lp<>-1) then _err_http_messaging;
        lp:=i;
        if not _get_content_length(@P^.nvp.nva[i],P^.FSend.DataSize) then
         err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
       end;
     3:begin//fphttp1_connection:
        if (cp<>-1) then _err_http_messaging;
        cp:=i;
        case _parse_connection(P^.nvp.nva[i].value,P^.nvp.nva[i].valuelen) of
         0:_set_KeepAlive(True);       //keep-alive
         1:P^.SetFlag(fphttp1_GOAWAY); //close
        end;
       end;
    10:begin//:status
        if (sp<>-1) then _err_http_messaging;
        if P^.nvp.nva[i].valuelen=0 then
        begin
         err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
        end;
        sp:=i;
        field_100:=_field_100(P^.nvp.nva[i].value,P^.nvp.nva[i].valuelen);
        P^.nvp.nva[i].namelen:=0; //no render
       end;
     4, //transfer-encoding
     5, //expect
     6, //:authority
     7, //:method
     8, //:path
     9: //:scheme
       begin
        err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
       end;
    end;
    if FSend.last_error<0 then Exit(FSend.last_error);
   end;

  if (sp=-1) then
  begin
   Exit(err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK));
  end;

  if field_100 then
  begin
   if (lp<>-1) then
   begin
    _err_http_messaging;
    if FSend.last_error<0 then Exit(FSend.last_error);
   end;

   if P^.GetFlag(fphttp1_EXPECT) then
   begin
    if _send_header_begin_cb(NGHTTP2_HCAT_HEADERS,P) then Exit(FSend.last_error);
   end else
   begin
    if _send_header_begin_cb(NGHTTP2_HCAT_RESPONSE,P) then Exit(FSend.last_error);
    //set end stream
    send_cb:=nil;
   end;

  end else
  begin
   send_cb:=@__send_data_buf;

   P^.RetFlag(fphttp1_EXPECT);
   if _send_header_begin_cb(NGHTTP2_HCAT_RESPONSE,P) then Exit(FSend.last_error);

   if P^.GetFlag(fphttp1_END_SUBMIT) then
   begin
    if P^.data_use then
    begin
     if (P^.FSend.DataSize<0) then
     begin
      if (FSettings.Version=11) then //auto chunked?
      begin
       P^.SetFlag(fphttp1_SEND_CHUNK);
       P^.nvp.insert_nocopy(fphttp1_tfe,Length(fphttp1_tfe),fphttp1_chunked,Length(fphttp1_chunked));
       //set chanked data
      end else
       P^.SetFlag(fphttp1_GOAWAY); //close on end stream
       //set trim data
     end;
    end else
    begin
     if (lp=-1) then
      P^.nvp.insert_nocopy(fphttp_ContL,Length(fphttp_ContL),fphttp_0,Length(fphttp_0))
     else
      P^.nvp._set_value_nocopy(lp,fphttp_0,Length(fphttp_0));
     //set end stream
     send_cb:=nil;
    end;
   end else
   begin
    if (P^.FSend.DataSize<0) then
    begin
     if (FSettings.Version=11) and P^.data_use then //auto chunked?
     begin
      P^.SetFlag(fphttp1_SEND_CHUNK);
      P^.nvp.insert_nocopy(fphttp1_tfe,Length(fphttp1_tfe),fphttp1_chunked,Length(fphttp1_chunked));
      //set chanked data
     end else
      P^.SetFlag(fphttp1_GOAWAY); //close on end stream
      //set trim data
    end;
   end;

  end;

  if GetFlag(fphttp1_upgrade) then
  begin
   P^.FSend.DataSize:=-1;
   send_cb:=@__send_data_buf;
  end;

  if P^.GetFlag(fphttp1_GOAWAY) then
  begin
   if GetFlag(fphttp1_alive) and (cp<>-1) then
   begin
    P^.nvp._set_value_nocopy(cp,fphttp1_close,Length(fphttp1_close));
   end;
  end;

  if (cp=-1) and (not field_100) then
   Case GetFlag(fphttp1_alive) of
    True :P^.nvp.insert_nocopy(fphttp1_con,Length(fphttp1_con),fphttp1_keep_alive,Length(fphttp1_keep_alive));
    False:P^.nvp.insert_nocopy(fphttp1_con,Length(fphttp1_con),fphttp1_close     ,Length(fphttp1_close));
   end;

  Result:=P^.nvp.render_response_headers(@Fblock,sp,FSettings.Version);
  data:=Fblock;

  if _closed_streams then
  begin
   P^.nvp.free;
  end else
  begin
   P^.nvp.clear;
  end;

  FSend.FrameSize:=0;

  if P^.GetFlag(fphttp1_EXPECT) then
  begin
   if _send_header_end_cb(NGHTTP2_HCAT_HEADERS,P,Result) then Exit(FSend.last_error);
   P^.RetFlag(fphttp1_EXPECT);
  end else
  begin
   if _send_header_end_cb(NGHTTP2_HCAT_RESPONSE,P,Result) then Exit(FSend.last_error);
  end;

 end;
end;

function _send_request_headers(session:Pfphttp1_session;P:Pfphttp1_stream;var data:Pointer):ssize_t;
Var
 i,lp,cp,mp,pp:ssize_t;

 Procedure _err_http_messaging; inline;
 begin
  With session^ do
   if (f_no_http_messaging in FSettings.nf) then
    FSend.last_error:=NGHTTP2_ERR_HTTP_MESSAGING;
 end;

begin
 Result:=0;

 if (P^.nvp.nvlen=0) then Exit;

 lp:=-1;
 cp:=-1;
 mp:=-1;
 pp:=-1;

 With session^ do
 begin
  P^.FSend.DataSize:=-1; //unknow size

  if not P^.nvp.is_clear then
   For i:=0 to P^.nvp.nvlen-1 do
   begin
    Case _field_cb_name(P^.nvp.nva[i].name,P^.nvp.nva[i].namelen) of
     1://NGHTTP2_content_length:
       begin
        if (lp<>-1) then _err_http_messaging;
        lp:=i;
        if not _get_content_length(@P^.nvp.nva[i],P^.FSend.DataSize) then
         err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
       end;
     3:begin//fphttp1_connection:
        if (cp<>-1) then _err_http_messaging;
        cp:=i;
        case _parse_connection(P^.nvp.nva[i].value,P^.nvp.nva[i].valuelen) of
         0:_set_KeepAlive(True);       //keep-alive
         1:P^.SetFlag(fphttp1_GOAWAY); //close
        end;
       end;
     5:begin //expect
        if _value_100_continue(P^.nvp.nva[i].value,P^.nvp.nva[i].valuelen) then
        begin
         P^.SetFlag(fphttp1_EXPECT);
        end else
        begin
         err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
        end;
       end;
     6:begin;//:authority
        P^.nvp._set_name_nocopy(i,fphttp1_hst,Length(fphttp1_hst));
       end;
     7:begin//:method
        if (mp<>-1) then _err_http_messaging;
        if P^.nvp.nva[i].valuelen=0 then
        begin
         err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
        end;
        mp:=i;
        P^.nvp.nva[i].namelen:=0; //no render
       end;
     8:begin//:path
        if (pp<>-1) then _err_http_messaging;
        if P^.nvp.nva[i].valuelen=0 then
        begin
         err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
        end;
        pp:=i;
        P^.nvp.nva[i].namelen:=0; //no render
       end;
     9:begin //:scheme
        P^.nvp.nva[i].namelen:=0; //no render
       end;
     4, //transfer-encoding
    10: //:status
       begin
        err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
       end;
    end;

    if FSend.last_error<0 then Exit(FSend.last_error);
   end;

  if (mp=-1) or (pp=-1) then
  begin
   Exit(err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK));
  end;

  if _send_header_begin_cb(NGHTTP2_HCAT_REQUEST,P) then Exit(FSend.last_error);

  if method_has_request_data(P^.nvp.nva[mp].value,P^.nvp.nva[mp].valuelen) then
  begin
   P^.SetFlag(fphttp1_HAS_REQS_D);
   //send data
   send_cb:=@__send_data_buf;
   if P^.data_use then
   begin
    if (P^.FSend.DataSize<0) then
    begin
     if (FSettings.Version=11) then //auto chunked?
     begin
      P^.SetFlag(fphttp1_SEND_CHUNK);
      P^.nvp.insert_nocopy(fphttp1_tfe,Length(fphttp1_tfe),fphttp1_chunked,Length(fphttp1_chunked));
     end else
      P^.SetFlag(fphttp1_GOAWAY); //close on end stream
    end else
    if (P^.FSend.DataSize=0) or (FSettings.Version=9) then
    begin
     //set end stream
     send_cb:=nil;
    end;
   end else
   if P^.GetFlag(fphttp1_END_SUBMIT) then
   begin
    if (lp=-1) then
     P^.nvp.insert_nocopy(fphttp_ContL,Length(fphttp_ContL),fphttp_0,Length(fphttp_0))
    else
     P^.nvp._set_value_nocopy(lp,fphttp_0,Length(fphttp_0));
    //set end stream
    send_cb:=nil;
   end else
   begin
    if (P^.FSend.DataSize<0) then
    begin
     if (FSettings.Version=11) then //auto chunked?
     begin
      P^.SetFlag(fphttp1_SEND_CHUNK);
      P^.nvp.insert_nocopy(fphttp1_tfe,Length(fphttp1_tfe),fphttp1_chunked,Length(fphttp1_chunked));
      //set chanked data
     end else
      P^.SetFlag(fphttp1_GOAWAY); //close on end stream
      //set trim data
    end;
   end;
  end else
  begin
   //set end stream
   send_cb:=nil;
   if (P^.FSend.DataSize>0) then
   begin
    err_send(NGHTTP2_ERR_INVALID_HEADER_BLOCK);
    Exit;
   end;
  end;

  if method_has_response_data(P^.nvp.nva[mp].value,P^.nvp.nva[mp].valuelen) then
  begin
   P^.SetFlag(fphttp1_HAS_RESP_D);
  end;

  if P^.GetFlag(fphttp1_GOAWAY) then
  begin
   if GetFlag(fphttp1_alive) and (cp<>-1) then
   begin
    P^.nvp._set_value_nocopy(cp,fphttp1_close,Length(fphttp1_close));
   end;
  end;

  if (cp=-1) then
   Case GetFlag(fphttp1_alive) of
    True :P^.nvp.insert_nocopy(fphttp1_con,Length(fphttp1_con),fphttp1_keep_alive,Length(fphttp1_keep_alive));
    False:P^.nvp.insert_nocopy(fphttp1_con,Length(fphttp1_con),fphttp1_close     ,Length(fphttp1_close));
   end;

  Result:=P^.nvp.render_request_headers(@Fblock,mp,pp,FSettings.Version);
  data:=Fblock;

  if _closed_streams then
  begin
   P^.nvp.free;
  end else
  begin
   P^.nvp.clear;
  end;

  FSend.FrameSize:=0;
  if _send_header_end_cb(NGHTTP2_HCAT_REQUEST,P,Result) then Exit(FSend.last_error);

 end;
end;

function Tfphttp1_session._send_data_buf(P:Pfphttp1_stream;var data_flags:uint32):ssize_t;
Var
 m:ssize_t;
 len:size_t;
begin
 Result:=0;
 data_flags:=0;
 if P^.FSend.data_prd.read_callback<>nil then
 begin
  len:=_on_get_data_source_read_length;
  if len=0 then
  begin
   Exit(err_send(NGHTTP2_ERR_CALLBACK_FAILURE));
  end;
  _mem_reserve(len);

  m:=P^.FSend.data_prd.read_callback(@Self,
                                     P^.Fstream_id,
                                     Fblock,len,
                                     @data_flags,
                                     @P^.FSend.data_prd.source,
                                     Fuser_data);
  Case m of
   NGHTTP2_ERR_PAUSE:Exit;
   NGHTTP2_ERR_DEFERRED:Exit;
   NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:
   begin
    if _closed_streams then _mem_free;
    Exit(err_send(m));
   end;
   else
    if m<0 then
    begin
     if _closed_streams then _mem_free;
     Exit(err_send(NGHTTP2_ERR_CALLBACK_FAILURE));
    end else
    begin
     Result:=m;
    end;
  end;

 end;
end;

function Tfphttp1_session._send_data_nocopy(P:Pfphttp1_stream;len:size_t;var data_flags:uint32):ssize_t;
Var
 m:ssize_t;
begin
 Result:=0;
 if _closed_streams then _mem_free;
 m:=_on_send_data_nocopy(P,len,@P^.FSend.data_prd.source,data_flags);
 Case m of
  0://all data will be send
  begin
   Result:=len;
  end;
  NGHTTP2_ERR_PAUSE     :Result:=0;
  NGHTTP2_ERR_WOULDBLOCK:Result:=0;
  NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE://rst
  begin
   Result:=err_send(m);
  end;
  else
   begin
    Result:=err_send(NGHTTP2_ERR_CALLBACK_FAILURE);
   end;
 end;
end;

function Tfphttp1_session._send_data_chunk(P:Pfphttp1_stream;var data_flags:uint32):ssize_t;
Const
 chunk_min_head_size=Length(fpchunk_head)+Length(fphttp1_NL)+Length(fpchunk_eof1)+Length(fphttp1_NL)+1;
 chunk_min_pos=Length(fpchunk_head);
 chunk_max_pos=Length(fphttp1_NL)+Length(fpchunk_eof1)+Length(fphttp1_NL);
Var
 m:ssize_t;
 len,new:size_t;
 F:Pointer;
 hex:string[4];

 procedure add(P:PChar;len:size_t); inline;
 begin
  Move(P^,PByte(Fblock)[new],len);
  new:=new+len;
 end;

begin
 Result:=0;
 data_flags:=0;
 //if P^.FSend.data_prd.read_callback<>nil then
 begin
  len:=_on_get_data_source_read_length;

  if len<(chunk_min_head_size) then
  begin
   Exit(err_send(NGHTTP2_ERR_CALLBACK_FAILURE));
  end;
  _mem_reserve(len);

  F:=@PByte(Fblock)[chunk_min_pos];
  new:=len-chunk_max_pos;

  m:=P^.FSend.data_prd.read_callback(@Self,
                                     P^.Fstream_id,
                                     F,new,
                                     @data_flags,
                                     @P^.FSend.data_prd.source,
                                     Fuser_data);
  Case m of
   NGHTTP2_ERR_PAUSE:Exit;
   NGHTTP2_ERR_DEFERRED:Exit;
   NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:
   begin
    if _closed_streams then _mem_free;
    Exit(err_send(m));
   end;
   else
    if m<0 then
    begin
     if _closed_streams then _mem_free;
     Exit(err_send(NGHTTP2_ERR_CALLBACK_FAILURE));
    end else
    begin
     Result:=m;

     if (data_flags and NGHTTP2_DATA_FLAG_NO_COPY=0) then
     begin
      if (data_flags and NGHTTP2_DATA_FLAG_EOF<>0) and (data_flags and NGHTTP2_DATA_FLAG_NO_END_STREAM=0) then
      begin

       new:=0;
       if m<>0 then
       begin
        hex:=hexStr(m,4);
        add(@hex[1],4);
        add(fphttp1_NL,Length(fphttp1_NL));  //begin chunk

        new:=m+Length(fpchunk_head);
        add(fphttp1_NL ,Length(fphttp1_NL)); //end chunk
       end;

       add(fpchunk_eof1,Length(fpchunk_eof1));
       if P^.nvp.is_clear then
       begin
        add(fphttp1_NL,Length(fphttp1_NL));
       end else
       begin
        new:=P^.nvp.render_trailers(new,@Fblock);
       end;
       add(fphttp1_NL,Length(fphttp1_NL));

       Result:=new;

      end else
      if m<>0 then
      begin
       hex:=hexStr(m,4);
       new:=0;
       add(@hex[1],4);
       add(fphttp1_NL,Length(fphttp1_NL));

       new:=m+Length(fpchunk_head);
       add(fphttp1_NL,Length(fphttp1_NL));
       Result:=new;
      end;
     end;

    end;
  end;

 end;

end;

procedure Tfphttp1_session._apply_send_FrameSize(P:Pfphttp1_stream;m:ssize_t);
begin
 if m<=0 then Exit;
 if P^.GetFlag(fphttp1_SEND_CHUNK) then
 begin
  FSend.FrameSize:=FSend.FrameSize+size_t(m);
 end else
 begin
  if P^.FSend.DataSize<0 then
  begin
   FSend.FrameSize:=FSend.FrameSize+size_t(m);
  end else
  begin
   FSend.FrameSize:=FSend.FrameSize+size_t(m);
   if FSend.FrameSize>P^.FSend.DataSize then
    err_send(NGHTTP2_ERR_FLOW_CONTROL);
  end;
 end;
end;

function _conv_data_flags(data_flags:uint32):Byte; inline;
begin
 Result:=0;
 if (data_flags and NGHTTP2_DATA_FLAG_EOF<>0) then
 begin
  if (data_flags and NGHTTP2_DATA_FLAG_NO_END_STREAM<>0) then
  begin
   Result:=1;
  end else
  begin
   Result:=2;
  end;
 end;
end;

function __send_data_buf(session:Pfphttp1_session;P:Pfphttp1_stream;var data:Pointer):ssize_t;
Var
 data_flags:uint32;
begin
 Result:=0;
 data_flags:=0;
 With session^ do
 begin

  if P^.GetFlag(fphttp1_SEND_CHUNK) then
  begin
   Result:=_send_data_chunk(P,data_flags);
  end else
  begin
   Result:=_send_data_buf(P,data_flags);
  end;

  if Result<0 then Exit;

  if (data_flags and NGHTTP2_DATA_FLAG_NO_COPY<>0) then
  begin
   Result:=_send_data_nocopy(P,Result,data_flags);
   data:=nil;
  end else
  begin
   data:=Fblock;
  end;

  if Result>=0 then
  begin
   case _conv_data_flags(data_flags) of
    1:P^.FSend.data_prd:=Default(Tnghttp2_data_provider);
    2:begin
       P^.FSend.data_prd:=Default(Tnghttp2_data_provider);
       //end stream
       if _send_data_end_cb(P^.Fstream_id,Result) then exit;
       send_cb:=nil;
      end;
   end;
   _apply_send_FrameSize(P,Result);
   if (data_flags and NGHTTP2_DATA_FLAG_NO_COPY<>0) then
   begin
    Result:=0;
   end;
  end;

 end;
end;

Procedure Tfphttp1_session._mem_reserve(size:Ptruint);
begin
 if Fblock=nil then
 begin
  Fblock:=GetMem(size);
 end else
 if size>MemSize(Fblock) then
 begin
  Fblock:=ReAllocMem(Fblock,size);
 end;
end;

Procedure Tfphttp1_session._mem_free; inline;
begin
 {$IFNDEF THREAD_LOCAL_SEND_BLOCK}
  FreeMem(Fblock);
  Fblock:=nil;
 {$ENDIF}
end;

procedure Tfphttp1_session._send_end_stream(is_recv:Boolean); inline;
begin
 drop_stream(is_recv);
 if not (GetFlag(fphttp1_alive) or pending_stream) then
 begin //close streams but NOT terminate
  close_all_streams(false,is_recv);
 end;
end;

function Tfphttp1_session._check_terminate:Boolean; inline;
begin
 Result:=False;
 if not GetFlag(fphttp1_alive) then
 begin
  Result:=true;
  _terminate;
 end;
end;

function Tfphttp1_session._send_header_begin_cb(cat:Tnghttp2_headers_category;P:Pfphttp1_stream):Boolean; inline;
begin
 Result:=_on_before_frame_send(cat,P);
 if Result then
 begin
  _on_header_frame_not_send(cat,P);
 end;
end;

function Tfphttp1_session._send_header_end_cb(cat:Tnghttp2_headers_category;P:Pfphttp1_stream;len:size_t):Boolean; inline;
begin
 Result:=False;
 if len>0 then
 begin
  Result:=_on_header_frame_send(cat,P,len);
  if Result then
  begin
   _on_header_frame_not_send(cat,P);
  end;
 end;
end;

function Tfphttp1_session._send_data_end_cb(stream_id:int32;len:size_t):Boolean; inline;
begin
 Result:=False;
 if len>0 then
 begin
  Result:=_on_data_frame_send(stream_id,len);
 end;
end;

function  fphttp1_session_mem_send(session:Pnghttp2_session;Var data_ptr:Puint8):ssize_t;cdecl;
Var
 P:Pfphttp1_stream;
Label
 ret;
begin
 Result:=0;
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 ret:
 With Pfphttp1_session(session)^ do
 if pending_stream then
 begin

  if GetFlag(fphttp1_server) then //server side
  begin
   P:=Fstreams.parent.Fprev;

   if send_cb=nil then
   begin
    if P^.GetFlag(fphttp1_RST) then
    begin
     send_cb:=@_send_rst;
    end else
    if FSettings.Version=9 then
    begin
     send_cb:=@__send_data_buf;
    end else
    begin
     send_cb:=@_send_response_headers;
    end;
   end;

   Result:=send_cb(Pfphttp1_session(session),P,data_ptr);

   if (Result<=0) then
   begin
    data_ptr:=nil;
   end else
   begin
    P^.Fstate:=NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE;
   end;

   if send_cb=nil then
   begin
    if P^.GetFlag(fphttp1_GOAWAY) then
    begin
     _set_KeepAlive(False);
    end;
    _send_end_stream(false);
    if _check_terminate then Exit(FSend.last_error);
   end;

  end else //client side
  begin
   P:=Fstreams.parent.Fnext;

   if send_cb=nil then
   begin
    if GetFlag(fphttp1_upgrade) then
    begin
     send_cb:=nil;
     Exit;
    end;
    if P^.Fstate<>NGHTTP2_STREAM_STATE_OPEN then Exit;
    if P^.GetFlag(fphttp1_RST) then
    begin
     P^.SetFlag(fphttp1_END_SUBMIT);
     if not step_next_stream then
     begin
      _send_end_stream(false);
     end;
     Goto ret;
    end else
    begin
     send_cb:=@_send_request_headers;
    end;
   end;

   Result:=send_cb(Pfphttp1_session(session),P,data_ptr);

   if (Result<=0) then
   begin
    data_ptr:=nil;
   end else
   begin
    P^.Fstate:=NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL;
   end;

   if send_cb=nil then
   begin
    step_next_stream;
   end;

  end;
 end else
 begin //not exist opened streams
  if _check_terminate then Exit(FSend.last_error);
 end;
end;

function fphttp1_session_send(session:Pnghttp2_session):cint;cdecl;
Var
 data_ptr:Puint8;
 m:ssize_t;
 id:uint32;
begin
 Result:=0;
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
 begin
  if not Assigned(Fcallbacks.Fsend_callback) then Exit;

  id:=fphttp1_session_get_next_stream_id(session);
  if id=0 then Exit;

  data_ptr:=nil;
  repeat
   m:=fphttp1_session_mem_send(session,data_ptr);
   if m<0 then Exit(m);
   if m=0 then Exit;

   m:=Fcallbacks.Fsend_callback(session,
                                data_ptr,m,
                                0,Fuser_data);

   Case m of
    NGHTTP2_ERR_WOULDBLOCK:;
    else
     if m<0 then
     begin
      err_send(NGHTTP2_ERR_CALLBACK_FAILURE);
      Exit(FSend.last_error);
     end;
    end;

  until (id<>fphttp1_session_get_next_stream_id(session));

 end;
end;

function fphttp1_session_recv(session:Pnghttp2_session):cint;cdecl;
Var
 m:ssize_t;
 id:int32;
 len:size_t;
begin
 Result:=0;
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
 begin
  if not Assigned(Fcallbacks.Frecv_callback) then Exit;

  id:=fphttp1_session_get_last_proc_stream_id(session);
  if id=0 then Exit;

  len:=Def_block_len;
  _mem_reserve(len);

  repeat
   m:=Fcallbacks.Frecv_callback(session,
                                Fblock,len,
                                0,Fuser_data);

   Case m of
    NGHTTP2_ERR_WOULDBLOCK:;
    else
     if m<0 then
     begin
      err_recv(NGHTTP2_ERR_CALLBACK_FAILURE);
      Exit(FHeaders.last_error);
     end;
    end;

   m:=fphttp1_session_mem_recv(session,Fblock,len);
   if m<0 then Exit(m);
   if m=0 then Exit;

  until (id<>fphttp1_session_get_last_proc_stream_id(session));

  if _closed_streams then _mem_free;
 end;
end;

function  fphttp1_session_get_local_settings(session:Pnghttp2_session;id:Tnghttp2_settings_id):uint32;cdecl;
begin
 Result:=0;
 if (session=nil) then Exit;
 With Pfphttp1_session(session)^ do
 case id of
  NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:Result:=FSettings.MAX_STREAMS;
  NGHTTP2_SETTINGS_MAX_FRAME_SIZE        :Result:=FSettings.MAX_FRAME_SIZE;
  NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE  :Result:=FSettings.MAX_HEADER_LIST_SIZE;
 end;
end;

function  fphttp1_submit_settings(session:Pnghttp2_session;flags:uint8;iv:Pnghttp2_settings_entry;niv:size_t):cint;cdecl;
Var
 i:size_t;
begin
 Result:=0;
 if (session=nil) or (iv=nil) or (niv=0) then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
  if niv>0 then
   For i:=0 to niv-1 do
    case iv[i].settings_id of
     NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:FSettings.MAX_STREAMS          :=iv[i].value;
     NGHTTP2_SETTINGS_MAX_FRAME_SIZE        :FSettings.MAX_FRAME_SIZE       :=iv[i].value;
     NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE  :FSettings.MAX_HEADER_LIST_SIZE :=iv[i].value;
    end;
end;

function  fphttp1_submit_response(session:Pnghttp2_session;stream_id:int32;nva:Pnghttp2_nv;nvlen:size_t;data_prd:Pnghttp2_data_provider):cint;cdecl;
Var
 stream:Pfphttp1_stream;
begin
 //this function half-closes the outbound stream.
 //NGHTTP2_ERR_PROTO - The session is client session.
 Result:=0;
 if (session=nil) or (nva=nil) or (nvlen=0) then Exit(NGHTTP2_ERR_NOMEM);
 if (stream_id=0) then Exit(NGHTTP2_ERR_INVALID_ARGUMENT);
 With Pfphttp1_session(session)^ do
  if not GetFlag(fphttp1_server) then Exit(NGHTTP2_ERR_PROTO);
 stream:=Pointer(fphttp1_session_find_stream(session,stream_id));
 if (stream=nil) then Exit(NGHTTP2_ERR_STREAM_CLOSED);

 if stream^.GetFlag(fphttp1_END_SUBMIT) then
 begin
  Result:=NGHTTP2_ERR_INVALID_STREAM_STATE;
  Exit;
 end;

 if (stream^.nvp.nvlen<>0) or (stream^.FSend.data_prd.read_callback<>nil) then Exit(NGHTTP2_ERR_DATA_EXIST);

 stream^.SetFlag(fphttp1_END_SUBMIT);
 stream^.nvp.copy(nva,nvlen);

 if data_prd<>nil then
 begin
  stream^.FSend.data_prd:=data_prd^;
 end;
end;

function  fphttp1_submit_request(session:Pnghttp2_session;pri_spec:Pnghttp2_priority_spec;nva:Pnghttp2_nv;nvlen:size_t;data_prd:Pnghttp2_data_provider;stream_user_data:pointer):int32;cdecl;
Var
 stream:Pfphttp1_stream;
begin
 Result:=0;
 if (session=nil) or (nva=nil) or (nvlen=0) then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
  if GetFlag(fphttp1_server) then Exit(NGHTTP2_ERR_PROTO);

 //open request stream
 stream:=Pfphttp1_session(session)^.resume_stream;
 if (stream=nil) then Exit(Pfphttp1_session(session)^.FHeaders.last_error);
 stream^.Fstate:=NGHTTP2_STREAM_STATE_OPEN;
 Result:=stream^.Fstream_id;

 stream^.Fuser_data:=stream_user_data;
 stream^.SetFlag(fphttp1_END_SUBMIT);
 stream^.nvp.copy(nva,nvlen);

 if data_prd<>nil then
 begin
  stream^.FSend.data_prd:=data_prd^;
 end;
end;

function  fphttp1_submit_headers(session:Pnghttp2_session;flags:uint8;stream_id:int32;pri_spec:Pnghttp2_priority_spec;nva:Pnghttp2_nv;nvlen:size_t;stream_user_data:pointer):int32;cdecl;
Var
 stream:Pfphttp1_stream;
begin
 //If the stream_id is -1 open request stream
 ///NGHTTP2_ERR_PROTO - The stream_id is -1, and session is server session.
 //
 Result:=stream_id;
 if (session=nil) or (nva=nil) or (nvlen=0) then Exit(NGHTTP2_ERR_NOMEM);

 Case stream_id of
   0:begin
      Pfphttp1_session(session)^.nva_config(nva,nvlen);
      Exit;
     end;
  -1:begin
      With Pfphttp1_session(session)^ do
       if GetFlag(fphttp1_server) then Exit(NGHTTP2_ERR_PROTO);
      //open request stream
      stream:=Pfphttp1_session(session)^.resume_stream;
      if (stream=nil) then Exit(Pfphttp1_session(session)^.FHeaders.last_error);
      stream^.Fstate:=NGHTTP2_STREAM_STATE_OPEN;
      Result:=stream^.Fstream_id;
      stream^.Fuser_data:=stream_user_data;
     end;
  else
    begin
     stream:=Pointer(fphttp1_session_find_stream(session,stream_id));
     if (stream=nil) then Exit(NGHTTP2_ERR_STREAM_CLOSED);
     if (stream^.nvp.nvlen<>0) then Exit(NGHTTP2_ERR_DATA_EXIST);

     if stream^.GetFlag(fphttp1_END_SUBMIT) then
     begin
      Result:=NGHTTP2_ERR_INVALID_STREAM_STATE;
      Exit;
     end;

     if (flags and NGHTTP2_FLAG_END_STREAM)<>0 then
     begin
      stream^.SetFlag(fphttp1_END_SUBMIT);
     end;

    end;
 end;

 stream^.nvp.copy(nva,nvlen);

end;

function  fphttp1_submit_trailer(session:Pnghttp2_session;stream_id:int32;nva:Pnghttp2_nv;nvlen:size_t):cint;cdecl;
Var
 stream:Pfphttp1_stream;
begin
 Result:=0;
 //This function returns 0 if it succeeds and stream_id is -1
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 if (stream_id=0) then Exit(NGHTTP2_ERR_INVALID_ARGUMENT);
 stream:=Pointer(fphttp1_session_find_stream(session,stream_id));
 if (stream=nil) then Exit(NGHTTP2_ERR_STREAM_CLOSED);

 if stream^.GetFlag(fphttp1_END_SUBMIT) and
    stream^.GetFlag(fphttp1_SEND_CHUNK) then
 begin
  if (stream^.nvp.nvlen<>0) then Exit(NGHTTP2_ERR_DATA_EXIST);
  stream^.nvp.copy(nva,nvlen);
 end else
 begin
  Result:=NGHTTP2_ERR_INVALID_STREAM_STATE;
 end;

end;

function  fphttp1_submit_data(session:Pnghttp2_session;flags:uint8;stream_id:int32;data_prd:Pnghttp2_data_provider):cint;cdecl;
Var
 stream:Pfphttp1_stream;
begin
 Result:=0;
 if (session=nil) or (data_prd=nil) then Exit(NGHTTP2_ERR_NOMEM);
 if (stream_id=0) then Exit(NGHTTP2_ERR_INVALID_ARGUMENT);
 stream:=Pointer(fphttp1_session_find_stream(session,stream_id));
 if (stream=nil) then Exit(NGHTTP2_ERR_STREAM_CLOSED);

 if stream^.GetFlag(fphttp1_END_SUBMIT) then
 begin
  Result:=NGHTTP2_ERR_INVALID_STREAM_STATE;
  Exit;
 end;

 if (stream^.FSend.data_prd.read_callback<>nil) then Exit(NGHTTP2_ERR_DATA_EXIST);

 if (flags and NGHTTP2_FLAG_END_STREAM)<>0 then
 begin
  stream^.SetFlag(fphttp1_END_SUBMIT);
 end;

 if data_prd<>nil then
 begin
  stream^.FSend.data_prd:=data_prd^;
 end;

end;

function  fphttp1_submit_goaway(session:Pnghttp2_session;flags:uint8;last_stream_id:int32;error_code:uint32;opaque_data:Puint8;opaque_data_len:size_t):cint;cdecl;
Var
 stream:Pfphttp1_stream;
begin
 Result:=0;
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
 begin
  if not pending_stream then
  begin
   close_all_streams(false,false);
   _terminate;
  end else
  begin
   if last_stream_id<>0 then
    stream:=Pointer(fphttp1_session_find_stream(session,last_stream_id))
   else
   if GetFlag(fphttp1_server) then
    stream:=Fstreams.parent.Fprev
   else
    stream:=Fstreams.parent.Fparent;
   if stream=nil then Exit;
   stream^.SetFlag(fphttp1_GOAWAY);
  end;
 end;
end;

function fphttp1_submit_shutdown_notice(session:Pnghttp2_session):cint;cdecl;
begin
 Result:=fphttp1_submit_goaway(session,0,fphttp1_session_get_last_proc_stream_id(session),0,nil,0);
end;

function fphttp1_submit_rst_stream(session:Pnghttp2_session;flags:uint8;stream_id:int32;error_code:uint32):cint;cdecl;
Var
 stream:Pfphttp1_stream;
begin
 Result:=0;
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 if (stream_id=0) then Exit(NGHTTP2_ERR_INVALID_ARGUMENT);
 stream:=Pointer(fphttp1_session_find_stream(session,stream_id));
 if (stream=nil) then Exit(NGHTTP2_ERR_STREAM_CLOSED);

 stream^.SetFlag(fphttp1_RST);
 stream^.nvp.clear;
end;

function fphttp1_session_upgrade(session:Pnghttp2_session;settings_payload:Puint8;settings_payloadlen:size_t;stream_user_data:pointer):cint;cdecl;
begin
 Result:=0;
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
 begin
  SetFlag(fphttp1_upgrade)
 end;
end;

function fphttp1_session_upgrade2(session:Pnghttp2_session;settings_payload:Puint8;settings_payloadlen:size_t;head_request:cint;stream_user_data:pointer):cint;cdecl;
begin
 Result:=0;
 if (session=nil) then Exit(NGHTTP2_ERR_NOMEM);
 With Pfphttp1_session(session)^ do
 begin
  SetFlag(fphttp1_upgrade)
 end;
end;

//no copy send

function nghttp2_send_frame_header(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;

 procedure _frame_pad; inline;
 Var
  _frame:array[0..9] of Byte;
 begin
  Move(framehd^,_frame,9);
  _frame[9]:=byte(frame^.data.padlen-1);
  Result:=cb(@_frame,10,user_data);
 end;

begin
 Result:=0;

 if (not Assigned(frame)) or
    (not Assigned(framehd)) or
    (not Assigned(cb)) then Exit;

 if (frame^.data.padlen>0) then
 begin
  _frame_pad;
 end else
 begin
  Result:=cb(framehd,9,user_data);
 end;

end;

function nghttp2_send_frame_footer(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;
Var
 _len:SizeUInt;
 _frame:Pointer;
begin
 Result:=0;

 if (not Assigned(frame)) or
    (not Assigned(framehd)) or
    (not Assigned(cb)) then Exit;

 _len:=frame^.data.padlen;

 if (_len>1) then
 begin
  _len:=_len-1;
  if _len>SizeOf(Pointer) then
  begin
   _frame:=AllocMem(_len);
   Result:=cb(_frame,_len,user_data);
   FreeMem(_frame);
  end else
  begin
   _frame:=nil;
   Result:=cb(@_frame,_len,user_data);
  end;
 end;
end;

function fphttp1_send_frame_header(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;
Var
 P:Pfphttp1_stream;
 hex:string[6];

begin
 Result:=0;

 if (not Assigned(frame)) or
    (not Assigned(framehd)) or
    (not Assigned(cb)) then Exit;

 P:=Pointer(framehd);

 if (not P^.GetFlag(fphttp1_SEND_CHUNK)) then Exit;

 if frame^.hd.length<>0 then
 begin
  hex:=hexStr(frame^.hd.length,4)+fphttp1_NL;
  Result:=cb(@hex[1],Length(fpchunk_head),user_data);
 end;
end;

function fphttp1_send_frame_footer(frame:Pnghttp2_frame;framehd:Puint8;cb:Theader_send_callback;user_data:pointer):ssize_t;
Var
 P:Pfphttp1_stream;
 Data:Pointer;

 procedure _move(i:ssize_t;P:PAnsiChar;L:ssize_t); inline;
 begin
  Move(P^,PByte(Data)[i],L);
 end;

begin
 Result:=0;

 if (not Assigned(frame)) or
    (not Assigned(framehd)) or
    (not Assigned(cb)) then Exit;

 P:=Pointer(framehd);

 if (not P^.GetFlag(fphttp1_SEND_CHUNK)) then Exit;

 if (frame^.hd.flags and NGHTTP2_DATA_FLAG_EOF<>0) and
    (frame^.hd.flags and NGHTTP2_DATA_FLAG_NO_END_STREAM=0) then
 begin

  if P^.nvp.is_clear then
  begin
   if frame^.hd.length<>0 then
   begin
    Result:=cb(Puint8(PAnsiChar(fpchunk_eof3)),Length(fpchunk_eof3),user_data);
   end else
   begin
    Result:=cb(Puint8(PAnsiChar(fpchunk_eof2)),Length(fpchunk_eof2),user_data);
   end;
  end else
  begin
   Result:=P^.nvp.render_trailers(0,nil)+Length(fphttp1_NL)+Length(fpchunk_eof1);

   if frame^.hd.length<>0 then
   begin
    Result:=Result+Length(fphttp1_NL);
    Data:=GetMem(Result);
    _move(0,fphttp1_NL,Length(fphttp1_NL));
    Result:=Length(fphttp1_NL);
   end else
   begin
    Data:=GetMem(Result);
    Result:=0;
   end;

   _move(Result,fpchunk_eof1,Length(fpchunk_eof1));
   Result:=Result+Length(fpchunk_eof1);

   Result:=P^.nvp.render_trailers(Result,@Data);

   _move(Result,fphttp1_NL,Length(fphttp1_NL));
   Result:=Result+Length(fphttp1_NL);

   //Writeln('*',GetStr(Data,Result)+'*');

   Result:=cb(Data,Result,user_data);
   FreeMem(data);
   P^.nvp.clear;

  end;

 end else
 if frame^.hd.length<>0 then
 begin
  Result:=cb(Puint8(PAnsiChar(fphttp1_NL)),Length(fphttp1_NL),user_data);
 end;

end;

{$IFDEF THREAD_LOCAL_SEND_BLOCK}
 var
  _ThreadInit,_ThreadDone:TProcedure;

 Procedure mtThreadInit;
 begin
  Fblock:=nil;
  if Assigned(_ThreadInit) then _ThreadInit();
 end;

 Procedure mtThreadFree;
 begin
  FreeMem(Fblock);
  Fblock:=nil;
  if Assigned(_ThreadDone) then _ThreadDone();
 end;

 Procedure Init;
 Var
  MM:TMemoryManager;
 begin
  _ThreadInit:=nil;
  _ThreadDone:=nil;
  mtThreadInit;

  MM:=Default(TMemoryManager);
  GetMemoryManager(MM);

  _ThreadInit  :=MM.InitThread;
  _ThreadDone  :=MM.DoneThread;

  MM.InitThread:=@mtThreadInit;
  MM.DoneThread:=@mtThreadFree;

  SetMemoryManager(MM);
 end;

 initialization
  Init;

{$ENDIF}

end.




