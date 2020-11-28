{
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
}

{
  Automatically converted by H2Pas 1.0.0 from nghttp2.h
  The following command line parameters were used:
    -e
    -C
    -T
    -p
    -c
    -S
    nghttp2.h
}

unit nghttp2;
interface

{$mode objfpc}{$H+}
{$codepage utf8}

{/$define USE_STATIC_NGHTTP2}
{/$define USE_CMEM}

{$ifdef USE_STATIC_NGHTTP2}
 {$Linklib nghttp2.a, static}
{$endif}

uses
 {$IFDEF USE_CMEM}
   cmem,
 {$endif}
  ctypes;

{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}

const
 NGHTTP2_LIB = 'libnghttp2';

Type
 size_t = NativeUInt;
 ssize_t = NativeInt;

 Pnghttp2_calloc  = ^Tnghttp2_calloc;
 Pnghttp2_data  = ^Tnghttp2_data;
 Pnghttp2_data_flag  = ^Tnghttp2_data_flag;
 Pnghttp2_data_provider  = ^Tnghttp2_data_provider;
 Pnghttp2_data_source  = ^Tnghttp2_data_source;
 Pnghttp2_error  = ^Tnghttp2_error;
 Pnghttp2_error_code  = ^Tnghttp2_error_code;
 Pnghttp2_ext_altsvc  = ^Tnghttp2_ext_altsvc;
 Pnghttp2_extension  = ^Tnghttp2_extension;
 Pnghttp2_flag  = ^Tnghttp2_flag;
 Pnghttp2_frame  = ^Tnghttp2_frame;
 Pnghttp2_frame_hd  = ^Tnghttp2_frame_hd;
 Pnghttp2_frame_type  = ^Tnghttp2_frame_type;
 Pnghttp2_goaway  = ^Tnghttp2_goaway;
 Pnghttp2_hd_deflater  = ^Tnghttp2_hd_deflater;
 Pnghttp2_hd_inflate_flag  = ^Tnghttp2_hd_inflate_flag;
 Pnghttp2_hd_inflater  = ^Tnghttp2_hd_inflater;
 Pnghttp2_headers  = ^Tnghttp2_headers;
 Pnghttp2_headers_category  = ^Tnghttp2_headers_category;
 Pnghttp2_info  = ^Tnghttp2_info;
 Pnghttp2_malloc  = ^Tnghttp2_malloc;
 Pnghttp2_mem  = ^Tnghttp2_mem;
 Pnghttp2_nv  = ^Tnghttp2_nv;
 Pnghttp2_nv_flag  = ^Tnghttp2_nv_flag;
 Pnghttp2_option  = ^Tnghttp2_option;
 Pnghttp2_ping  = ^Tnghttp2_ping;
 Pnghttp2_priority  = ^Tnghttp2_priority;
 Pnghttp2_priority_spec  = ^Tnghttp2_priority_spec;
 Pnghttp2_push_promise  = ^Tnghttp2_push_promise;
 Pnghttp2_rcbuf  = ^Tnghttp2_rcbuf;
 Pnghttp2_realloc  = ^Tnghttp2_realloc;
 Pnghttp2_rst_stream  = ^Tnghttp2_rst_stream;
 Pnghttp2_session  = ^Tnghttp2_session;
 Pnghttp2_session_callbacks  = ^Tnghttp2_session_callbacks;
 Pnghttp2_settings  = ^Tnghttp2_settings;
 Pnghttp2_settings_entry  = ^Tnghttp2_settings_entry;
 Pnghttp2_settings_id  = ^Tnghttp2_settings_id;
 Pnghttp2_stream  = ^Tnghttp2_stream;
 Pnghttp2_stream_proto_state  = ^Tnghttp2_stream_proto_state;
 Pnghttp2_vec  = ^Tnghttp2_vec;
 Pnghttp2_window_update  = ^Tnghttp2_window_update;

 Tnghttp2_session = record
  {undefined structure}
 end;

 Tnghttp2_info = record
     age : cint;
     version_num : cint;
     version_str : PAnsiChar;
     proto_str : PAnsiChar;
   end;

 Tnghttp2_error =  Longint;

 Tnghttp2_vec = record
     base : Puint8;
     len : size_t;
 end;

 Tnghttp2_rcbuf = record
  {undefined structure}
 end;

 Tnghttp2_nv_flag =  Longint;

 Tnghttp2_nv = record
      name : Puint8;
      value : Puint8;
      namelen : size_t;
      valuelen : size_t;
      flags : uint8;
 end;

 Tnghttp2_frame_type =  Longint;

 Tnghttp2_flag =  Longint;

 Tnghttp2_settings_id =  Longint;

 Tnghttp2_error_code =  Longint;

 Tnghttp2_frame_hd = record
     length : size_t;
     stream_id : int32;
     _type : uint8;
     flags : uint8;
     reserved : uint8;
 end;

 Tnghttp2_data_source = record
     case longint of
       0 : ( fd : cint );
       1 : ( ptr : pointer );
 end;

 Tnghttp2_data_flag =  Longint;

 Tnghttp2_data_source_read_callback = function (session:Pnghttp2_session;
              stream_id:int32; buf:Puint8; length:size_t; data_flags:Puint32;
              source:Pnghttp2_data_source; user_data:pointer):ssize_t;cdecl;

 Tnghttp2_data_provider = record
     source : Tnghttp2_data_source;
     read_callback : Tnghttp2_data_source_read_callback;
 end;

 Tnghttp2_data = record
     hd : Tnghttp2_frame_hd;
     padlen : size_t;
 end;

 Tnghttp2_headers_category =  Longint;

 Tnghttp2_priority_spec = record
     stream_id : int32;
     weight : int32;
     exclusive : uint8;
 end;

 Tnghttp2_headers = record
     hd : Tnghttp2_frame_hd;
     padlen : size_t;
     pri_spec : Tnghttp2_priority_spec;
     nva : Pnghttp2_nv;
     nvlen : size_t;
     cat : Tnghttp2_headers_category;
 end;

 Tnghttp2_priority = record
     hd : Tnghttp2_frame_hd;
     pri_spec : Tnghttp2_priority_spec;
 end;

 Tnghttp2_rst_stream = record
     hd : Tnghttp2_frame_hd;
     error_code : uint32;
 end;

 Tnghttp2_settings_entry = record
     settings_id : int32;
     value : uint32;
 end;

 Tnghttp2_settings = record
     hd : Tnghttp2_frame_hd;
     niv : size_t;
     iv : Pnghttp2_settings_entry;
 end;

 Tnghttp2_push_promise = record
     hd : Tnghttp2_frame_hd;
     padlen : size_t;
     nva : Pnghttp2_nv;
     nvlen : size_t;
     promised_stream_id : int32;
     reserved : uint8;
 end;

 Tnghttp2_ping = record
     hd : Tnghttp2_frame_hd;
     opaque_data : array[0..7] of uint8;
 end;

 Tnghttp2_goaway = record
     hd : Tnghttp2_frame_hd;
     last_stream_id : int32;
     error_code : uint32;
     opaque_data : Puint8;
     opaque_data_len : size_t;
     reserved : uint8;
 end;

 Tnghttp2_window_update = record
     hd : Tnghttp2_frame_hd;
     window_size_increment : int32;
     reserved : uint8;
 end;

 Tnghttp2_extension = record
     hd : Tnghttp2_frame_hd;
     payload : pointer;
 end;

 Tnghttp2_frame = record
     case longint of
       0 : ( hd : Tnghttp2_frame_hd );
       1 : ( data : Tnghttp2_data );
       2 : ( headers : Tnghttp2_headers );
       3 : ( priority : Tnghttp2_priority );
       4 : ( rst_stream : Tnghttp2_rst_stream );
       5 : ( settings : Tnghttp2_settings );
       6 : ( push_promise : Tnghttp2_push_promise );
       7 : ( ping : Tnghttp2_ping );
       8 : ( goaway : Tnghttp2_goaway );
       9 : ( window_update : Tnghttp2_window_update );
       10 : ( ext : Tnghttp2_extension );
  end;

 Tnghttp2_send_callback = function (session:Pnghttp2_session; data:Puint8;
              length:size_t; flags:cint; user_data:pointer):ssize_t;cdecl;

 Tnghttp2_send_data_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; framehd:Puint8; length:size_t; source:Pnghttp2_data_source;
              user_data:pointer):cint;cdecl;

 Tnghttp2_recv_callback = function (session:Pnghttp2_session; buf:Puint8;
              length:size_t; flags:cint; user_data:pointer):ssize_t;cdecl;

 Tnghttp2_on_frame_recv_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; user_data:pointer):cint;cdecl;

 Tnghttp2_on_invalid_frame_recv_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; lib_error_code:cint; user_data:pointer):cint;cdecl;

 Tnghttp2_on_data_chunk_recv_callback = function (session:Pnghttp2_session;
              flags:uint8; stream_id:int32; data:Puint8; len:size_t;
              user_data:pointer):cint;cdecl;

 Tnghttp2_before_frame_send_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; user_data:pointer):cint;cdecl;

 Tnghttp2_on_frame_send_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; user_data:pointer):cint;cdecl;

 Tnghttp2_on_frame_not_send_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; lib_error_code:cint; user_data:pointer):cint;cdecl;

 Tnghttp2_on_stream_close_callback = function (session:Pnghttp2_session;
              stream_id:int32; error_code:uint32; user_data:pointer):cint;cdecl;

 Tnghttp2_on_begin_headers_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; user_data:pointer):cint;cdecl;

 Tnghttp2_on_header_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; name:Puint8; namelen:size_t; value:Puint8;
              valuelen:size_t; flags:uint8; user_data:pointer):cint;cdecl;

 Tnghttp2_on_header_callback2 = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; name:Pnghttp2_rcbuf; value:Pnghttp2_rcbuf; flags:uint8;
              user_data:pointer):cint;cdecl;

 Tnghttp2_on_invalid_header_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; name:Puint8; namelen:size_t; value:Puint8;
              valuelen:size_t; flags:uint8; user_data:pointer):cint;cdecl;

 Tnghttp2_on_invalid_header_callback2 = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; name:Pnghttp2_rcbuf; value:Pnghttp2_rcbuf; flags:uint8;
              user_data:pointer):cint;cdecl;

 Tnghttp2_select_padding_callback = function (session:Pnghttp2_session;
              frame:Pnghttp2_frame; max_payloadlen:size_t; user_data:pointer):ssize_t;cdecl;

 Tnghttp2_data_source_read_length_callback = function (session:Pnghttp2_session;
              frame_type:uint8; stream_id:int32; session_remote_window_size:int32; stream_remote_window_size:int32;
              remote_max_frame_size:uint32; user_data:pointer):ssize_t;cdecl;

 Tnghttp2_on_begin_frame_callback = function (session:Pnghttp2_session;
              hd:Pnghttp2_frame_hd; user_data:pointer):cint;cdecl;

 Tnghttp2_on_extension_chunk_recv_callback = function (session:Pnghttp2_session;
              hd:Pnghttp2_frame_hd; data:Puint8; len:size_t; user_data:pointer):cint;cdecl;

 Tnghttp2_unpack_extension_callback = function (session:Pnghttp2_session;
              payload:Ppointer; hd:Pnghttp2_frame_hd; user_data:pointer):cint;cdecl;

 Tnghttp2_pack_extension_callback = function (session:Pnghttp2_session;
              buf:Puint8; len:size_t; frame:Pnghttp2_frame; user_data:pointer):ssize_t;cdecl;

 Tnghttp2_error_callback = function (session:Pnghttp2_session; msg:pcchar;
              len:size_t; user_data:pointer):cint;cdecl;

 Tnghttp2_error_callback2 = function (session:Pnghttp2_session;
              lib_error_code:cint; msg:pcchar; len:size_t; user_data:pointer):cint;cdecl;

 Tnghttp2_session_callbacks = record
     {undefined structure}
 end;

 Tnghttp2_malloc = function (size:size_t; mem_user_data:pointer):pointer;cdecl;

 Tnghttp2_free = procedure (ptr:pointer; mem_user_data:pointer);cdecl;

 Tnghttp2_calloc = function (nmemb:size_t; size:size_t; mem_user_data:pointer):pointer;cdecl;

 Tnghttp2_realloc = function (ptr:pointer; size:size_t; mem_user_data:pointer):pointer;cdecl;

 Tnghttp2_mem = record
     mem_user_data : pointer;
     malloc : Tnghttp2_malloc;
     free : Tnghttp2_free;
     calloc : Tnghttp2_calloc;
     realloc : Tnghttp2_realloc;
   end;

 Tnghttp2_option = record
     {undefined structure}
 end;

 Tnghttp2_ext_altsvc = record
     origin : Puint8;
     origin_len : size_t;
     field_value : Puint8;
     field_value_len : size_t;
 end;

 Tnghttp2_hd_deflater = record
     {undefined structure}
 end;

 Tnghttp2_hd_inflater = record
     {undefined structure}
 end;

 Tnghttp2_hd_inflate_flag =  Longint;

 Tnghttp2_stream = record
     {undefined structure}
 end;

 Tnghttp2_stream_proto_state =  Longint;

 //Tnghttp2_debug_vprintf_callback = procedure (format:pcchar; args:va_list);cdecl;

Const
 NGHTTP2_authority                  =':authority'                 ;
 NGHTTP2_method                     =':method'                    ;
 NGHTTP2_path                       =':path'                      ;
 NGHTTP2_scheme                     =':scheme'                    ;
 NGHTTP2_status                     =':status'                    ;
 NGHTTP2_accept_charset             ='accept-charset'             ;
 NGHTTP2_accept_encoding            ='accept-encoding'            ;
 NGHTTP2_accept_language            ='accept-language'            ;
 NGHTTP2_accept_ranges              ='accept-ranges'              ;
 NGHTTP2_accept                     ='accept'                     ;
 NGHTTP2_access_control_allow_origin='access-control-allow-origin';
 NGHTTP2_age                        ='age'                        ;
 NGHTTP2_allow                      ='allow'                      ;
 NGHTTP2_authorization              ='authorization'              ;
 NGHTTP2_cache_control              ='cache-control'              ;
 NGHTTP2_content_disposition        ='content-disposition'        ;
 NGHTTP2_content_encoding           ='content-encoding'           ;
 NGHTTP2_content_language           ='content-language'           ;
 NGHTTP2_content_length             ='content-length'             ;
 NGHTTP2_content_location           ='content-location'           ;
 NGHTTP2_content_range              ='content-range'              ;
 NGHTTP2_content_type               ='content-type'               ;
 NGHTTP2_cookie                     ='cookie'                     ;
 NGHTTP2_date                       ='date'                       ;
 NGHTTP2_etag                       ='etag'                       ;
 NGHTTP2_expect                     ='expect'                     ;
 NGHTTP2_expires                    ='expires'                    ;
 NGHTTP2_from                       ='from'                       ;
 NGHTTP2_host                       ='host'                       ;
 NGHTTP2_if_match                   ='if-match'                   ;
 NGHTTP2_if_modified_since          ='if-modified-since'          ;
 NGHTTP2_if_none_match              ='if-none-match'              ;
 NGHTTP2_if_range                   ='if-range'                   ;
 NGHTTP2_if_unmodified_since        ='if-unmodified-since'        ;
 NGHTTP2_last_modified              ='last-modified'              ;
 NGHTTP2_link                       ='link'                       ;
 NGHTTP2_location                   ='location'                   ;
 NGHTTP2_max_forwards               ='max-forwards'               ;
 NGHTTP2_proxy_authenticate         ='proxy-authenticate'         ;
 NGHTTP2_proxy_authorization        ='proxy-authorization'        ;
 NGHTTP2_range                      ='range'                      ;
 NGHTTP2_referer                    ='referer'                    ;
 NGHTTP2_refresh                    ='refresh'                    ;
 NGHTTP2_retry_after                ='retry-after'                ;
 NGHTTP2_server                     ='server'                     ;
 NGHTTP2_set_cookie                 ='set-cookie'                 ;
 NGHTTP2_strict_transport_security  ='strict-transport-security'  ;
 NGHTTP2_transfer_encoding          ='transfer-encoding'          ;
 NGHTTP2_user_agent                 ='user-agent'                 ;
 NGHTTP2_vary                       ='vary'                       ;
 NGHTTP2_via                        ='via'                        ;
 NGHTTP2_www_authenticate           ='www-authenticate'           ;

 NGHTTP2_HTTP_1_1_ALPN              =#8'http/1.1';
 NGHTTP2_HTTP_1_1_ALPN_LEN          =(Length(NGHTTP2_HTTP_1_1_ALPN)-1);

 NGHTTP2_PROTO_ALPN                 =#2'h2';
 NGHTTP2_PROTO_ALPN_LEN             =(Length(NGHTTP2_PROTO_ALPN)-1);

 NGHTTP2_DEFAULT_WEIGHT                =16;
 NGHTTP2_MAX_WEIGH                     =256;
 NGHTTP2_MIN_WEIGHT                    =1;
 NGHTTP2_MAX_WINDOW_SIZE               =(1 shl 31)-1;
 NGHTTP2_INITIAL_WINDOW_SIZE           =(1 shl 16)-1;
 NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE=(1 shl 16)-1;
 NGHTTP2_DEFAULT_HEADER_TABLE_SIZE     =1 shl 12;
 NGHTTP2_CLIENT_MAGIC                  ='PRI * HTTP/2.0'#13#10#13#10'SM'#13#10#13#10;
 NGHTTP2_CLIENT_MAGIC_LEN              =24;

 NGHTTP2_ERR_INVALID_ARGUMENT = -(501);
 NGHTTP2_ERR_BUFFER_ERROR = -(502);
 NGHTTP2_ERR_UNSUPPORTED_VERSION = -(503);
 NGHTTP2_ERR_WOULDBLOCK = -(504);
 NGHTTP2_ERR_PROTO = -(505);
 NGHTTP2_ERR_INVALID_FRAME = -(506);
 NGHTTP2_ERR_EOF = -(507);
 NGHTTP2_ERR_DEFERRED = -(508);
 NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE = -(509);
 NGHTTP2_ERR_STREAM_CLOSED = -(510);
 NGHTTP2_ERR_STREAM_CLOSING = -(511);
 NGHTTP2_ERR_STREAM_SHUT_WR = -(512);
 NGHTTP2_ERR_INVALID_STREAM_ID = -(513);
 NGHTTP2_ERR_INVALID_STREAM_STATE = -(514);
 NGHTTP2_ERR_DEFERRED_DATA_EXIST = -(515);
 NGHTTP2_ERR_START_STREAM_NOT_ALLOWED = -(516);
 NGHTTP2_ERR_GOAWAY_ALREADY_SENT = -(517);
 NGHTTP2_ERR_INVALID_HEADER_BLOCK = -(518);
 NGHTTP2_ERR_INVALID_STATE = -(519);
 NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE = -(521);
 NGHTTP2_ERR_FRAME_SIZE_ERROR = -(522);
 NGHTTP2_ERR_HEADER_COMP = -(523);
 NGHTTP2_ERR_FLOW_CONTROL = -(524);
 NGHTTP2_ERR_INSUFF_BUFSIZE = -(525);
 NGHTTP2_ERR_PAUSE = -(526);
 NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS = -(527);
 NGHTTP2_ERR_PUSH_DISABLED = -(528);
 NGHTTP2_ERR_DATA_EXIST = -(529);
 NGHTTP2_ERR_SESSION_CLOSING = -(530);
 NGHTTP2_ERR_HTTP_HEADER = -(531);
 NGHTTP2_ERR_HTTP_MESSAGING = -(532);
 NGHTTP2_ERR_REFUSED_STREAM = -(533);
 NGHTTP2_ERR_INTERNAL = -(534);
 NGHTTP2_ERR_CANCEL = -(535);
 NGHTTP2_ERR_SETTINGS_EXPECTED = -(536);
 NGHTTP2_ERR_FATAL = -(900);
 NGHTTP2_ERR_NOMEM = -(901);
 NGHTTP2_ERR_CALLBACK_FAILURE = -(902);
 NGHTTP2_ERR_BAD_CLIENT_MAGIC = -(903);
 NGHTTP2_ERR_FLOODED = -(904);

 NGHTTP2_NV_FLAG_NONE = 0;
 NGHTTP2_NV_FLAG_NO_INDEX = $01;
 NGHTTP2_NV_FLAG_NO_COPY_NAME = $02;
 NGHTTP2_NV_FLAG_NO_COPY_VALUE = $04;

 NGHTTP2_DATA = 0;
 NGHTTP2_HEADERS = $01;
 NGHTTP2_PRIORITY = $02;
 NGHTTP2_RST_STREAM = $03;
 NGHTTP2_SETTINGS = $04;
 NGHTTP2_PUSH_PROMISE = $05;
 NGHTTP2_PING = $06;
 NGHTTP2_GOAWAY = $07;
 NGHTTP2_WINDOW_UPDATE = $08;
 NGHTTP2_CONTINUATION = $09;
 NGHTTP2_ALTSVC = $0a;
 NGHTTP2_ORIGIN = $0c;

 NGHTTP2_FLAG_NONE = 0;
 NGHTTP2_FLAG_END_STREAM = $01;
 NGHTTP2_FLAG_END_HEADERS = $04;
 NGHTTP2_FLAG_ACK = $01;
 NGHTTP2_FLAG_PADDED = $08;
 NGHTTP2_FLAG_PRIORITY = $20;

 NGHTTP2_SETTINGS_HEADER_TABLE_SIZE = $01;
 NGHTTP2_SETTINGS_ENABLE_PUSH = $02;
 NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = $03;
 NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE = $04;
 NGHTTP2_SETTINGS_MAX_FRAME_SIZE = $05;
 NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = $06;
 NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL = $08;

 NGHTTP2_NO_ERROR = $00;
 NGHTTP2_PROTOCOL_ERROR = $01;
 NGHTTP2_INTERNAL_ERROR = $02;
 NGHTTP2_FLOW_CONTROL_ERROR = $03;
 NGHTTP2_SETTINGS_TIMEOUT = $04;
 NGHTTP2_STREAM_CLOSED = $05;
 NGHTTP2_FRAME_SIZE_ERROR = $06;
 NGHTTP2_REFUSED_STREAM = $07;
 NGHTTP2_CANCEL = $08;
 NGHTTP2_COMPRESSION_ERROR = $09;
 NGHTTP2_CONNECT_ERROR = $0a;
 NGHTTP2_ENHANCE_YOUR_CALM = $0b;
 NGHTTP2_INADEQUATE_SECURITY = $0c;
 NGHTTP2_HTTP_1_1_REQUIRED = $0d;

 NGHTTP2_DATA_FLAG_NONE = 0;
 NGHTTP2_DATA_FLAG_EOF = $01;
 NGHTTP2_DATA_FLAG_NO_END_STREAM = $02;
 NGHTTP2_DATA_FLAG_NO_COPY = $04;

 NGHTTP2_HCAT_REQUEST = 0;
 NGHTTP2_HCAT_RESPONSE = 1;
 NGHTTP2_HCAT_PUSH_RESPONSE = 2;
 NGHTTP2_HCAT_HEADERS = 3;

 NGHTTP2_HD_INFLATE_NONE = 0;
 NGHTTP2_HD_INFLATE_FINAL = $01;
 NGHTTP2_HD_INFLATE_EMIT = $02;

 NGHTTP2_STREAM_STATE_IDLE = 1;
 NGHTTP2_STREAM_STATE_OPEN = 2;
 NGHTTP2_STREAM_STATE_RESERVED_LOCAL = 3;
 NGHTTP2_STREAM_STATE_RESERVED_REMOTE = 4;
 NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL = 5;
 NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE = 6;
 NGHTTP2_STREAM_STATE_CLOSED = 7;

procedure nghttp2_rcbuf_incref(rcbuf:Pnghttp2_rcbuf);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_rcbuf_decref(rcbuf:Pnghttp2_rcbuf);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_rcbuf_get_buf(rcbuf:Pnghttp2_rcbuf):Tnghttp2_vec;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_rcbuf_is_static(rcbuf:Pnghttp2_rcbuf):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_callbacks_new(Var callbacks_ptr:Pnghttp2_session_callbacks):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_del(callbacks:Pnghttp2_session_callbacks);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_send_callback(cbs:Pnghttp2_session_callbacks; send_callback:Tnghttp2_send_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_recv_callback(cbs:Pnghttp2_session_callbacks; recv_callback:Tnghttp2_recv_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_frame_recv_callback(cbs:Pnghttp2_session_callbacks; on_frame_recv_callback:Tnghttp2_on_frame_recv_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cbs:Pnghttp2_session_callbacks; on_invalid_frame_recv_callback:Tnghttp2_on_invalid_frame_recv_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs:Pnghttp2_session_callbacks; on_data_chunk_recv_callback:Tnghttp2_on_data_chunk_recv_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_before_frame_send_callback(cbs:Pnghttp2_session_callbacks; before_frame_send_callback:Tnghttp2_before_frame_send_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_frame_send_callback(cbs:Pnghttp2_session_callbacks; on_frame_send_callback:Tnghttp2_on_frame_send_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_frame_not_send_callback(cbs:Pnghttp2_session_callbacks; on_frame_not_send_callback:Tnghttp2_on_frame_not_send_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_stream_close_callback(cbs:Pnghttp2_session_callbacks; on_stream_close_callback:Tnghttp2_on_stream_close_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_begin_headers_callback(cbs:Pnghttp2_session_callbacks; on_begin_headers_callback:Tnghttp2_on_begin_headers_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_header_callback(cbs:Pnghttp2_session_callbacks; on_header_callback:Tnghttp2_on_header_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_header_callback2(cbs:Pnghttp2_session_callbacks; on_header_callback2:Tnghttp2_on_header_callback2);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_invalid_header_callback(cbs:Pnghttp2_session_callbacks; on_invalid_header_callback:Tnghttp2_on_invalid_header_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_invalid_header_callback2(cbs:Pnghttp2_session_callbacks; on_invalid_header_callback2:Tnghttp2_on_invalid_header_callback2);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_select_padding_callback(cbs:Pnghttp2_session_callbacks; select_padding_callback:Tnghttp2_select_padding_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_data_source_read_length_callback(cbs:Pnghttp2_session_callbacks; data_source_read_length_callback:Tnghttp2_data_source_read_length_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_begin_frame_callback(cbs:Pnghttp2_session_callbacks; on_begin_frame_callback:Tnghttp2_on_begin_frame_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_send_data_callback(cbs:Pnghttp2_session_callbacks; send_data_callback:Tnghttp2_send_data_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_pack_extension_callback(cbs:Pnghttp2_session_callbacks; pack_extension_callback:Tnghttp2_pack_extension_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_unpack_extension_callback(cbs:Pnghttp2_session_callbacks; unpack_extension_callback:Tnghttp2_unpack_extension_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_on_extension_chunk_recv_callback(cbs:Pnghttp2_session_callbacks; on_extension_chunk_recv_callback:Tnghttp2_on_extension_chunk_recv_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_error_callback(cbs:Pnghttp2_session_callbacks; error_callback:Tnghttp2_error_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_callbacks_set_error_callback2(cbs:Pnghttp2_session_callbacks; error_callback2:Tnghttp2_error_callback2);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_option_new(Var option_ptr:Pnghttp2_option):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_del(option:Pnghttp2_option);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_no_auto_window_update(option:Pnghttp2_option; val:cint);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_peer_max_concurrent_streams(option:Pnghttp2_option; val:uint32);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_no_recv_client_magic(option:Pnghttp2_option; val:cint);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_no_http_messaging(option:Pnghttp2_option; val:cint);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_max_reserved_remote_streams(option:Pnghttp2_option; val:uint32);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_user_recv_extension_type(option:Pnghttp2_option; _type:uint8);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_builtin_recv_extension_type(option:Pnghttp2_option; _type:uint8);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_no_auto_ping_ack(option:Pnghttp2_option; val:cint);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_max_send_header_block_length(option:Pnghttp2_option; val:size_t);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_max_deflate_dynamic_table_size(option:Pnghttp2_option; val:size_t);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_no_closed_streams(option:Pnghttp2_option; val:cint);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_client_new(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_server_new(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_client_new2(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer; option:Pnghttp2_option):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_server_new2(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer; option:Pnghttp2_option):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_client_new3(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer; option:Pnghttp2_option; mem:Pnghttp2_mem):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_server_new3(Var session_ptr:Pnghttp2_session; callbacks:Pnghttp2_session_callbacks; user_data:pointer; option:Pnghttp2_option; mem:Pnghttp2_mem):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_del(session:Pnghttp2_session);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_send(session:Pnghttp2_session):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_mem_send(session:Pnghttp2_session;Var data_ptr:Puint8):ssize_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_recv(session:Pnghttp2_session):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_mem_recv(session:Pnghttp2_session; _in:Puint8; inlen:size_t):ssize_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_resume_data(session:Pnghttp2_session; stream_id:int32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_want_read(session:Pnghttp2_session):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_want_write(session:Pnghttp2_session):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_stream_user_data(session:Pnghttp2_session; stream_id:int32):pointer;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_set_stream_user_data(session:Pnghttp2_session; stream_id:int32; stream_user_data:pointer):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_session_set_user_data(session:Pnghttp2_session;user_data:pointer);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_outbound_queue_size(session:Pnghttp2_session):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_stream_effective_recv_data_length(session:Pnghttp2_session; stream_id:int32):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_stream_effective_local_window_size(session:Pnghttp2_session; stream_id:int32):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_stream_local_window_size(session:Pnghttp2_session; stream_id:int32):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_effective_recv_data_length(session:Pnghttp2_session):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_effective_local_window_size(session:Pnghttp2_session):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_local_window_size(session:Pnghttp2_session):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_stream_remote_window_size(session:Pnghttp2_session; stream_id:int32):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_remote_window_size(session:Pnghttp2_session):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_stream_local_close(session:Pnghttp2_session; stream_id:int32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_stream_remote_close(session:Pnghttp2_session; stream_id:int32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_hd_inflate_dynamic_table_size(session:Pnghttp2_session):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_hd_deflate_dynamic_table_size(session:Pnghttp2_session):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_terminate_session(session:Pnghttp2_session; error_code:uint32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_terminate_session2(session:Pnghttp2_session; last_stream_id:int32; error_code:uint32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_shutdown_notice(session:Pnghttp2_session):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_remote_settings(session:Pnghttp2_session; id:Tnghttp2_settings_id):uint32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_local_settings(session:Pnghttp2_session; id:Tnghttp2_settings_id):uint32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_set_next_stream_id(session:Pnghttp2_session; next_stream_id:int32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_next_stream_id(session:Pnghttp2_session):uint32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_consume(session:Pnghttp2_session; stream_id:int32; size:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_consume_connection(session:Pnghttp2_session; size:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_consume_stream(session:Pnghttp2_session; stream_id:int32; size:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_change_stream_priority(session:Pnghttp2_session; stream_id:int32; pri_spec:Pnghttp2_priority_spec):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_create_idle_stream(session:Pnghttp2_session; stream_id:int32; pri_spec:Pnghttp2_priority_spec):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_upgrade(session:Pnghttp2_session; settings_payload:Puint8; settings_payloadlen:size_t; stream_user_data:pointer):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_upgrade2(session:Pnghttp2_session; settings_payload:Puint8; settings_payloadlen:size_t; head_request:cint; stream_user_data:pointer):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_pack_settings_payload(buf:Puint8; buflen:size_t; iv:Pnghttp2_settings_entry; niv:size_t):ssize_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_strerror(lib_error_code:cint):pcchar;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_http2_strerror(error_code:uint32):pcchar;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_priority_spec_init(pri_spec:Pnghttp2_priority_spec; stream_id:int32; weight:int32; exclusive:cint);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_priority_spec_default_init(pri_spec:Pnghttp2_priority_spec);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_priority_spec_check_default(pri_spec:Pnghttp2_priority_spec):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_request(session:Pnghttp2_session; pri_spec:Pnghttp2_priority_spec; nva:Pnghttp2_nv; nvlen:size_t; data_prd:Pnghttp2_data_provider; 
           stream_user_data:pointer):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_response(session:Pnghttp2_session; stream_id:int32; nva:Pnghttp2_nv; nvlen:size_t; data_prd:Pnghttp2_data_provider):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_trailer(session:Pnghttp2_session; stream_id:int32; nva:Pnghttp2_nv; nvlen:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_headers(session:Pnghttp2_session; flags:uint8; stream_id:int32; pri_spec:Pnghttp2_priority_spec; nva:Pnghttp2_nv; 
           nvlen:size_t; stream_user_data:pointer):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_data(session:Pnghttp2_session; flags:uint8; stream_id:int32; data_prd:Pnghttp2_data_provider):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_priority(session:Pnghttp2_session; flags:uint8; stream_id:int32; pri_spec:Pnghttp2_priority_spec):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_rst_stream(session:Pnghttp2_session; flags:uint8; stream_id:int32; error_code:uint32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_settings(session:Pnghttp2_session; flags:uint8; iv:Pnghttp2_settings_entry; niv:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_push_promise(session:Pnghttp2_session; flags:uint8; stream_id:int32; nva:Pnghttp2_nv; nvlen:size_t; 
           promised_stream_user_data:pointer):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_ping(session:Pnghttp2_session; flags:uint8; opaque_data:Puint8):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_goaway(session:Pnghttp2_session; flags:uint8; last_stream_id:int32; error_code:uint32; opaque_data:Puint8; 
           opaque_data_len:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_last_proc_stream_id(session:Pnghttp2_session):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_check_request_allowed(session:Pnghttp2_session):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_check_server_session(session:Pnghttp2_session):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_window_update(session:Pnghttp2_session; flags:uint8; stream_id:int32; window_size_increment:int32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_set_local_window_size(session:Pnghttp2_session; flags:uint8; stream_id:int32; window_size:int32):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_extension(session:Pnghttp2_session; _type:uint8; flags:uint8; stream_id:int32; payload:pointer):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_submit_altsvc(session:Pnghttp2_session; flags:uint8; stream_id:int32; origin:Puint8; origin_len:size_t; 
           field_value:Puint8; field_value_len:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_nv_compare_name(lhs:Pnghttp2_nv; rhs:Pnghttp2_nv):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_select_next_protocol(Var out_:Pcuchar; outlen:pcuchar; in_:pcuchar; inlen:cuint):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_version(least_version:cint):Pnghttp2_info;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_is_fatal(lib_error_code:cint):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_check_header_name(name:Puint8; len:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_check_header_value(value:Puint8; len:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_new(Var deflater_ptr:Pnghttp2_hd_deflater; max_deflate_dynamic_table_size:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_new2(Var deflater_ptr:Pnghttp2_hd_deflater; max_deflate_dynamic_table_size:size_t; mem:Pnghttp2_mem):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_hd_deflate_del(deflater:Pnghttp2_hd_deflater);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_change_table_size(deflater:Pnghttp2_hd_deflater; settings_max_dynamic_table_size:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_hd(deflater:Pnghttp2_hd_deflater; buf:Puint8; buflen:size_t; nva:Pnghttp2_nv; nvlen:size_t):ssize_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_hd_vec(deflater:Pnghttp2_hd_deflater; vec:Pnghttp2_vec; veclen:size_t; nva:Pnghttp2_nv; nvlen:size_t):ssize_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_bound(deflater:Pnghttp2_hd_deflater; nva:Pnghttp2_nv; nvlen:size_t):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_get_num_table_entries(deflater:Pnghttp2_hd_deflater):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_get_table_entry(deflater:Pnghttp2_hd_deflater; idx:size_t):Pnghttp2_nv;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_get_dynamic_table_size(deflater:Pnghttp2_hd_deflater):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_deflate_get_max_dynamic_table_size(deflater:Pnghttp2_hd_deflater):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_new(Var inflater_ptr:Pnghttp2_hd_inflater):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_new2(Var inflater_ptr:Pnghttp2_hd_inflater; mem:Pnghttp2_mem):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_hd_inflate_del(inflater:Pnghttp2_hd_inflater);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_change_table_size(inflater:Pnghttp2_hd_inflater; settings_max_dynamic_table_size:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_hd(inflater:Pnghttp2_hd_inflater; nv_out:Pnghttp2_nv; inflate_flags:pcint; in_:Puint8; inlen:size_t; 
           in_final:cint):ssize_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_hd2(inflater:Pnghttp2_hd_inflater; nv_out:Pnghttp2_nv; inflate_flags:pcint; in_:Puint8; inlen:size_t; 
           in_final:cint):ssize_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_end_headers(inflater:Pnghttp2_hd_inflater):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_get_num_table_entries(inflater:Pnghttp2_hd_inflater):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_get_table_entry(inflater:Pnghttp2_hd_inflater; idx:size_t):Pnghttp2_nv;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_get_dynamic_table_size(inflater:Pnghttp2_hd_inflater):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_hd_inflate_get_max_dynamic_table_size(inflater:Pnghttp2_hd_inflater):size_t;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_find_stream(session:Pnghttp2_session; stream_id:int32):Pnghttp2_stream;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_state(stream:Pnghttp2_stream):Tnghttp2_stream_proto_state;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_session_get_root_stream(session:Pnghttp2_session):Pnghttp2_stream;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_parent(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_stream_id(stream:Pnghttp2_stream):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_next_sibling(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_previous_sibling(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_first_child(stream:Pnghttp2_stream):Pnghttp2_stream;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_weight(stream:Pnghttp2_stream):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_stream_get_sum_dependency_weight(stream:Pnghttp2_stream):int32;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

//procedure nghttp2_set_debug_vprintf_callback(debug_vprintf_callback:Tnghttp2_debug_vprintf_callback);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_nv_array_sort(nva:Pnghttp2_nv;nvlen:size_t);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function  nghttp2_check_authority(value:PAnsiChar;len:size_t):cint;cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_max_outbound_ack(option:Pnghttp2_option;val:size_t);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

procedure nghttp2_option_set_max_settings(option:Pnghttp2_option;val:size_t);cdecl; external {$ifndef USE_STATIC_NGHTTP2} NGHTTP2_LIB {$endif};

function MAKE_NV(name,value:PChar;no_index:boolean=false):Tnghttp2_nv; inline;
function make_nv_nocopy(name,value:PChar;no_index:boolean=false):Tnghttp2_nv; inline;
function make_nv_nocopy_name(name,value:PChar):Tnghttp2_nv; inline;

implementation

function make_nv_internal(name,value:PChar;no_index:boolean;nv_flags:Byte):Tnghttp2_nv; inline;
begin
 if no_index then
  nv_flags:=nv_flags or NGHTTP2_NV_FLAG_NO_INDEX
 else
  nv_flags:=nv_flags or NGHTTP2_NV_FLAG_NONE;
 Result.name    :=Puint8(name);
 Result.value   :=Puint8(value);
 Result.namelen :=StrLen(name);
 Result.valuelen:=StrLen(value);
 Result.flags   :=nv_flags;
end;

function MAKE_NV(name,value:PChar;no_index:boolean=false):Tnghttp2_nv; inline;
begin
 Result:=make_nv_internal(PChar(name),PChar(value),no_index,NGHTTP2_NV_FLAG_NONE);
end;

function make_nv_nocopy(name,value:PChar;no_index:boolean=false):Tnghttp2_nv; inline;
begin
 Result:=make_nv_internal(PChar(name),PChar(value),no_index,NGHTTP2_NV_FLAG_NO_COPY_NAME or NGHTTP2_NV_FLAG_NO_COPY_VALUE);
end;

function make_nv_nocopy_name(name,value:PChar):Tnghttp2_nv; inline;
begin
 Result:=make_nv_internal(PChar(name),PChar(value),false,NGHTTP2_NV_FLAG_NO_COPY_NAME);
end;


{$ifdef USE_STATIC_NGHTTP2}

{$IFDEF USE_CMEM}
function __calloc(nelem,elsize:size_t):Pointer; cdecl; export; alias:'calloc';
begin
 Result:=CAlloc(nelem,elsize);
end;

function _calloc(nelem,elsize:size_t):Pointer; cdecl; export;
begin
 Result:=CAlloc(nelem,elsize);
end;

procedure __free(P:Pointer); cdecl; export; alias:'free';
begin
 Free(P);
end;

procedure _free(P:Pointer); cdecl; export;
begin
 Free(P);
end;

function __malloc(size:size_t):Pointer; cdecl; export; alias:'malloc';
begin
 Result:=malloc(size);
end;

function _malloc(size:size_t):Pointer; cdecl; export;
begin
 Result:=malloc(size);
end;

function __realloc(ptr:Pointer;newsize:size_t):Pointer; cdecl; export; alias:'realloc';
begin
 Result:=realloc(ptr,newsize);
end;

function _realloc(ptr:Pointer;newsize:size_t):Pointer; cdecl; export;
begin
 Result:=realloc(ptr,newsize);
end;

{$ELSE}
function calloc(nelem,elsize:size_t):Pointer; cdecl; export;
begin
 Result:=AllocMem(nelem*elsize);
end;

function _calloc(nelem,elsize:size_t):Pointer; cdecl; export;
begin
 Result:=AllocMem(nelem*elsize);
end;

procedure free(P:Pointer); cdecl; export;
begin
 FreeMem(P);
end;

procedure _free(P:Pointer); cdecl; export;
begin
 FreeMem(P);
end;

function malloc(size:size_t):Pointer; cdecl; export;
begin
 Result:=GetMem(size);
end;

function _malloc(size:size_t):Pointer; cdecl; export;
begin
 Result:=GetMem(size);
end;

function realloc(ptr:Pointer;newsize:size_t):Pointer; cdecl; export;
begin
 Result:=ReAllocMem(ptr,newsize);
end;

function _realloc(ptr:Pointer;newsize:size_t):Pointer; cdecl; export;
begin
 Result:=ReAllocMem(ptr,newsize);
end;

{$ENDIF}

function ___udivdi3(a,b:cuint64):cuint64; cdecl; export;
begin
 if (b=0) then Exit(0);
 Result:=a div b;
end;

function ___umoddi3(a,b:cuint64):cuint64; cdecl; export;
begin
 if (b=0) then Exit(0);
 Result:=a mod b;
end;

procedure _assert(__assertion,__file,__line:PChar); cdecl; export;
Var
 lineno:longint;
 Error:word;
begin
 if Assigned(AssertErrorProc) then
 begin
  lineno:=0;
  Val(__line,lineno,Error);
  AssertErrorProc(__assertion,__file,lineno,get_caller_addr(get_frame));
 end;
end;

procedure __assert(__assertion,__file,__line:PChar); cdecl; export;
Var
 lineno:longint;
 Error:word;
begin
 if Assigned(AssertErrorProc) then
 begin
  lineno:=0;
  Val(__line,lineno,Error);
  AssertErrorProc(__assertion,__file,lineno,get_caller_addr(get_frame));
 end;
end;

procedure ___chkstk_ms; cdecl; export;
begin
end;

procedure abort; cdecl; export;
begin
 Halt;
end;

procedure _abort; cdecl; export;
begin
 Halt;
end;

function __ms_vsnprintf(d:PChar;n:size_t;format:PChar;arg:Pointer):cint; cdecl; export;
begin
 Result:=-1;
end;

function ___ms_vsnprintf(d:PChar;n:size_t;format:PChar;arg:Pointer):cint; cdecl; export;
begin
 Result:=-1;
end;

function fprintf(stream:Pointer;format:PChar;arg_ptr:Pointer):cint; cdecl; export;
begin
 Result:=-1;
end;

function _fprintf(stream:Pointer;format:PChar;arg_ptr:Pointer):cint; cdecl; export;
begin
 Result:=-1;
end;

function fputc(char:cint;stream:Pointer):cint; cdecl; export;
begin
 Result:=-1;
end;

function _fputc(char:cint;stream:Pointer):cint; cdecl; export;
begin
 Result:=-1;
end;

function strlen(P:PChar):size_t; cdecl; export;
begin
 Result:=System.strlen(P);
end;

function _strlen(P:PChar):size_t; cdecl; export;
begin
 Result:=System.strlen(P);
end;

function _memcpy(dst,src:Pointer;len:size_t):Pointer; cdecl; export;
begin
 Result:=dst;
 Move(src^,dst^,len);
end;

function memcpy(dst,src:Pointer;len:size_t):Pointer; cdecl; export;
begin
 Result:=dst;
 Move(src^,dst^,len);
end;

function memset(ptr:Pointer;value:cint;num:size_t):Pointer; cdecl; export;
begin
 Result:=ptr;
 FillChar(ptr^,num,byte(value));
end;

function _memset(ptr:Pointer;value:cint;num:size_t):Pointer; cdecl; export;
begin
 Result:=ptr;
 FillChar(ptr^,num,byte(value));
end;

function memcmp(buf1,buf2:Pointer;count:size_t):cint; cdecl; export;
begin
 Result:=CompareByte(buf1^,buf2^,count);
end;

function _memcmp(buf1,buf2:Pointer;count:size_t):cint; cdecl; export;
begin
 Result:=CompareByte(buf1^,buf2^,count);
end;

function memmove(dst,src:Pointer;num:size_t):Pointer; cdecl; export;
begin
 Result:=dst;
 Move(src^,dst^,num);
end;

function _memmove(dst,src:Pointer;num:size_t):Pointer; cdecl; export;
begin
 Result:=dst;
 Move(src^,dst^,num);
end;

function __imp___iob_func():Pointer; cdecl; export;
begin
 Result:=nil;
end;

function __imp___iob():Pointer; cdecl; export;
begin
 Result:=nil;
end;

{$I qsort.inc}

Procedure _qsort(pbase:Pointer;total_elems,size:size_t;cmp:Tqsort_comparator); cdecl; export;
begin
 qsort(pbase,total_elems,size,cmp);
end;

{$endif}

end.

