{ Openssl library headers

 Copyright (C) 2018-2020 Red_prig                                                          |

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 DAMAGE.
}

unit openssl;
interface

uses
  ctypes,dynlibs;

{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}


{$IFDEF WINDOWS}
 {$IFDEF CPUX86_64}
  const
   DLLSSLName = 'libssl-1_1-x64';
   DLLUtilName = 'libcrypto-1_1-x64';
 {$ELSE}
  const
   DLLSSLName = 'libssl-1_1';
   DLLUtilName = 'libcrypto-1_1';
 {$ENDIF}
{$ELSE}
 const
  DLLSSLName = 'libssl';
  DLLUtilName = 'libcrypto';
{$ENDIF}


const
  CT_F_CTLOG_NEW = 117;
  CT_F_CTLOG_NEW_FROM_BASE64 = 118;
  CT_F_CTLOG_NEW_FROM_CONF = 119;
  CT_F_CTLOG_STORE_LOAD_CTX_NEW = 122;
  CT_F_CTLOG_STORE_LOAD_FILE = 123;
  CT_F_CTLOG_STORE_LOAD_LOG = 130;
  CT_F_CTLOG_STORE_NEW = 131;
  CT_F_CT_BASE64_DECODE = 124;
  CT_F_CT_POLICY_EVAL_CTX_NEW = 133;
  CT_F_CT_V1_LOG_ID_FROM_PKEY = 125;
  CT_F_I2O_SCT = 107;
  CT_F_I2O_SCT_LIST = 108;
  CT_F_I2O_SCT_SIGNATURE = 109;
  CT_F_O2I_SCT = 110;
  CT_F_O2I_SCT_LIST = 111;
  CT_F_O2I_SCT_SIGNATURE = 112;
  CT_F_SCT_CTX_NEW = 126;
  CT_F_SCT_CTX_VERIFY = 128;
  CT_F_SCT_NEW = 100;
  CT_F_SCT_NEW_FROM_BASE64 = 127;
  CT_F_SCT_SET0_LOG_ID = 101;
  CT_F_SCT_SET1_EXTENSIONS = 114;
  CT_F_SCT_SET1_LOG_ID = 115;
  CT_F_SCT_SET1_SIGNATURE = 116;
  CT_F_SCT_SET_LOG_ENTRY_TYPE = 102;
  CT_F_SCT_SET_SIGNATURE_NID = 103;
  CT_F_SCT_SET_VERSION = 104;
  CT_R_BASE64_DECODE_ERROR = 108;
  CT_R_INVALID_LOG_ID_LENGTH = 100;
  CT_R_LOG_CONF_INVALID = 109;
  CT_R_LOG_CONF_INVALID_KEY = 110;
  CT_R_LOG_CONF_MISSING_DESCRIPTION = 111;
  CT_R_LOG_CONF_MISSING_KEY = 112;
  CT_R_LOG_KEY_INVALID = 113;
  CT_R_SCT_FUTURE_TIMESTAMP = 116;
  CT_R_SCT_INVALID = 104;
  CT_R_SCT_INVALID_SIGNATURE = 107;
  CT_R_SCT_LIST_INVALID = 105;
  CT_R_SCT_LOG_ID_MISMATCH = 114;
  CT_R_SCT_NOT_SET = 106;
  CT_R_SCT_UNSUPPORTED_VERSION = 115;
  CT_R_UNRECOGNIZED_SIGNATURE_NID = 101;
  CT_R_UNSUPPORTED_ENTRY_TYPE = 102;
  CT_R_UNSUPPORTED_VERSION = 103;
  SSL_SESSION_ASN1_VERSION = $0001;
  SSL_MAX_SSL_SESSION_ID_LENGTH = 32;
  SSL_MAX_SID_CTX_LENGTH = 32;
  SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES = 512/8;
  SSL_MAX_KEY_ARG_LENGTH = 8;
  SSL_MAX_MASTER_KEY_LENGTH = 48;
  SSL_MAX_PIPELINES = 32;

  SSL_SENT_SHUTDOWN = 1;
  SSL_RECEIVED_SHUTDOWN = 2;

Type
 cint=ctypes.cint;
 clong=ctypes.clong;

 size_t = NativeUInt;
 ssize_t = NativeInt;
 time_t=DWORD;
 Ptime_t=^time_t;

 Psize_t  = ^size_t;

 Ppbyte=^pbyte;
 PPpbyte=^Ppbyte;
 PPuint8=^Puint8;

 Tcprocedure=Procedure; cdecl;
 TPfunction=function:Pointer; cdecl;

 Ptm=^tm;
 tm=record
  tm_sec  ,
  tm_min  ,
  tm_hour ,
  tm_mday ,
  tm_mon  ,
  tm_year ,
  tm_wday ,
  tm_yday ,
  tm_isdst:cint;
 end;

 POPENSSL_INIT_SETTINGS = ^Tossl_init_settings_st;
 Tossl_init_settings_st = record
  appname : PChar;
 end;

 Pssl_method = ^Tssl_method_st;

 PPBIO=^PBIO;
 PBIO=^bio_st;

 Tbio_info_cb=procedure(b:PBIO;oper:cint;ptr:PChar;arg1:cint;arg2,arg3:clong); cdecl;

 Tasn1_ps_func=procedure(b:PBIO;pbuf:PPointer;plen:Pcint;parg:Pointer); cdecl;
 PPasn1_ps_func=^Tasn1_ps_func;

 TBio_meth_bwrite       =function(para1:PBIO; para2:pbyte; para3:cint):cint; cdecl;
 TBio_meth_bread        =function(para1:PBIO; para2:pbyte; para3:cint):cint; cdecl;
 TBio_meth_bputs        =function(para1:PBIO; para2:pbyte):cint; cdecl;
 TBio_meth_bgets        =function(para1:PBIO; para2:pbyte; para3:cint):cint; cdecl;
 TBio_meth_ctrl         =function(para1:PBIO; para2:cint; para3:clong; para4:pointer):clong; cdecl;
 TBio_meth_create       =function(para1:PBIO):cint; cdecl;
 TBio_meth_destroy      =function(para1:PBIO):cint; cdecl;
 TBio_meth_callback_ctrl=function(para1:PBIO; para2:cint; para3:Tbio_info_cb):clong; cdecl;

 PBIO_METHOD=^bio_method_st;
 bio_method_st=record
  _type:cint;
  name : PChar;
  bwrite       :TBio_meth_bwrite;
  bread        :TBio_meth_bread;
  bputs        :TBio_meth_bputs;
  bgets        :TBio_meth_bgets;
  ctrl         :TBio_meth_ctrl;
  create       :TBio_meth_create;
  destroy      :TBio_meth_destroy;
  callback_ctrl:TBio_meth_callback_ctrl;
 end;

 Pbuf_mem=^buf_mem_st;
 buf_mem_st=record
  length:size_t;              // current number of bytes
  data:PByte;
  max:size_t;                 // size of buffer
  flags:culong;
 end;

 TBIO_callback_fn=function(b:PBIO;oper:cint;argp:pbyte;argi:cint;argl:clong;ret:clong):clong;cdecl;
 TBIO_callback_fn_ex=function(b:PBIO;oper:cint;argp:PChar;len:size_t;argi:cint;argl:clong;ret:cint;var processed:size_t):clong;

 TCRYPTO_REF_COUNT=cint;

 Pstack_st_void = ^Tstack_st_void;
 Tstack_st_void = record
  {undefined structure}
 end;

 Pcrypto_ex_data = ^Tcrypto_ex_data_st;
 Tcrypto_ex_data_st = record
  sk:Pstack_st_void;
 end;

 PCRYPTO_RWLOCK = ^TCRYPTO_RWLOCK;
 TCRYPTO_RWLOCK = pointer;

 bio_st=record
  method:PBIO_METHOD;
  // bio, mode, argp, argi, argl, ret
  callback:TBIO_callback_fn;
  callback_ex:TBIO_callback_fn_ex;
  cb_arg:Pointer;  // first argument for the callback
  init,
  shutdown,
  flags,           // extra storage */
  retry_reason,
  num:cint;
  ptr:Pointer;
  next_bio,prev_bio:PBIO;  // used by filter BIOs */
  references:TCRYPTO_REF_COUNT;
  num_read,
  num_write:culong;
  ex_data:Tcrypto_ex_data_st;
  lock:PCRYPTO_RWLOCK;
 end;

 bio_bio_st=record
  peer:PBIO; { NULL if buf == NULL. If peer != NULL, then
             * peer->ptr is also a bio_bio_st, and its
             * "peer" member points back to us. peer !=
             * NULL iff init != 0 in the BIO. }
  // This is for what we write (i.e. reading uses peer's struct): */
  closed:cint;                // valid iff peer != NULL
  len:size_t;                 // valid iff buf != NULL; 0 if peer == NULL
  offset:size_t;              // valid iff buf != NULL; 0 if len == 0
  size:size_t;
  buf:PByte;                  // "size" elements (if != NULL)
  request:size_t;             { valid iff peer != NULL; 0 if len != 0,
                               * otherwise set by peer to number of bytes
                               * it (unsuccessfully) tried to read, never
                               * more than buffer space (size-len)
                               * warrants. }
 end;

 // BIO memory stores buffer and read pointer
 bio_buf_mem_st=record
  buf:Pbuf_mem;   // allocated buffer
  readp:Pbuf_mem; // read pointer
 end;

  {
  * The valid handshake states (one for each type message sent and one for each
  * type of message received). There are also two "special" states:
  * TLS = TLS or DTLS state
  * DTLS = DTLS specific state
  * CR/SR = Client Read/Server Read
  * CW/SW = Client Write/Server Write
  *
  * The "special" states are:
  * TLS_ST_BEFORE = No handshake has been initiated yet
  * TLS_ST_OK = A handshake has been successfully completed
  }

  TOSSL_HANDSHAKE_STATE=(
     TLS_ST_BEFORE,
     TLS_ST_OK,
     DTLS_ST_CR_HELLO_VERIFY_REQUEST,
     TLS_ST_CR_SRVR_HELLO,
     TLS_ST_CR_CERT,
     TLS_ST_CR_CERT_STATUS,
     TLS_ST_CR_KEY_EXCH,
     TLS_ST_CR_CERT_REQ,
     TLS_ST_CR_SRVR_DONE,
     TLS_ST_CR_SESSION_TICKET,
     TLS_ST_CR_CHANGE,
     TLS_ST_CR_FINISHED,
     TLS_ST_CW_CLNT_HELLO,
     TLS_ST_CW_CERT,
     TLS_ST_CW_KEY_EXCH,
     TLS_ST_CW_CERT_VRFY,
     TLS_ST_CW_CHANGE,
     TLS_ST_CW_NEXT_PROTO,
     TLS_ST_CW_FINISHED,
     TLS_ST_SW_HELLO_REQ,
     TLS_ST_SR_CLNT_HELLO,
     DTLS_ST_SW_HELLO_VERIFY_REQUEST,
     TLS_ST_SW_SRVR_HELLO,
     TLS_ST_SW_CERT,
     TLS_ST_SW_KEY_EXCH,
     TLS_ST_SW_CERT_REQ,
     TLS_ST_SW_SRVR_DONE,
     TLS_ST_SR_CERT,
     TLS_ST_SR_KEY_EXCH,
     TLS_ST_SR_CERT_VRFY,
     TLS_ST_SR_NEXT_PROTO,
     TLS_ST_SR_CHANGE,
     TLS_ST_SR_FINISHED,
     TLS_ST_SW_SESSION_TICKET,
     TLS_ST_SW_CERT_STATUS,
     TLS_ST_SW_CHANGE,
     TLS_ST_SW_FINISHED);

 TWORK_STATE=(
   // Something went wrong
   WORK_ERROR,
   // We're done working and there shouldn't be anything else to do after
   WORK_FINISHED_STOP,
   // We're done working move onto the next thing
   WORK_FINISHED_CONTINUE,
   // We're working on phase A
   WORK_MORE_A,
   // We're working on phase B
   WORK_MORE_B);

 ossl_statem_st=record
  state:(
   // No handshake in progress
   MSG_FLOW_UNINITED,
   // A permanent error with this connection
   MSG_FLOW_ERROR,
   // We are about to renegotiate
   MSG_FLOW_RENEGOTIATE,
   // We are reading messages
   MSG_FLOW_READING,
   // We are writing messages
   MSG_FLOW_WRITING,
   // Handshake has finished
   MSG_FLOW_FINISHED);
  write_state:(
   WRITE_STATE_TRANSITION,
   WRITE_STATE_PRE_WORK,
   WRITE_STATE_SEND,
   WRITE_STATE_POST_WORK);
  write_state_work:TWORK_STATE;
  read_state:(
   READ_STATE_HEADER,
   READ_STATE_BODY,
   READ_STATE_POST_PROCESS);
  read_state_work:TWORK_STATE;
  hand_state:TOSSL_HANDSHAKE_STATE;
  in_init:cint;
  read_state_first_init:cint;
  // true when we are actually in SSL_accept() or SSL_connect()
  in_handshake:cint;
  // Should we skip the CertificateVerify message?
  no_cert_verify:cint;
  use_timer:cint;
 end;

 PX509_VERIFY_PARAM=Pointer;
 PPX509_VERIFY_PARAM=^PX509_VERIFY_PARAM;

 PSSL = ^Tssl_st;

 Tssl_msg_callback_cb=procedure (write_p:cint; version:cint; content_type:cint; buf:pointer; len:size_t; ssl:PSSL; arg:pointer);cdecl;

 Tssl_st = record
     version : cint;
     method : PSSL_METHOD;
     rbio : PBIO;
     wbio : PBIO;
     bbio : PBIO;
     rwstate : cint;
     handshake_func : function  (para1:PSSL):cint;cdecl;
     server : cint;
     new_session : cint;
     quiet_shutdown : cint;
     shutdown : cint;
     statem : ossl_statem_st;
     init_buf : pointer;
     init_msg : pointer;
     init_num : cint;
     init_off : cint;
     s3 : pointer;
     d1 : pointer;
     msg_callback : Tssl_msg_callback_cb;
     msg_callback_arg : pointer;
     hit : cint;
     param : PX509_VERIFY_PARAM;
     //-----------------
   end;

 Pbio_ssl = ^Tbio_ssl_st;
 Tbio_ssl_st = record
     ssl : PSSL;
     num_renegotiates :cint;
     renegotiate_count : culong;
     byte_count : culong;
     renegotiate_timeout : culong;
     last_time : culong;
   end;

 PPSSL_CIPHER=^Pssl_cipher;
 Pssl_cipher = ^Tssl_cipher_st;
 Tssl_cipher_st = record
     valid : uint32;
     name : pbyte;
     id : uint32;
     algorithm_mkey : uint32;
     algorithm_auth : uint32;
     algorithm_enc : uint32;
     algorithm_mac : uint32;
     min_tls : cint;
     max_tls : cint;
     min_dtls : cint;
     max_dtls : cint;
     algo_strength : uint32;
     algorithm2 : uint32;
     strength_bits : int32;
     alg_bits : uint32;
   end;

 Pssl_session = ^Tssl_session_st;
 Tssl_session_st = record
     ssl_version : cint;
     master_key_length : cint;
     master_key : array[0..(SSL_MAX_MASTER_KEY_LENGTH)-1] of byte;
     session_id_length : cuint;
     session_id : array[0..(SSL_MAX_SSL_SESSION_ID_LENGTH)-1] of byte;
     sid_ctx_length : cuint;
     sid_ctx : array[0..(SSL_MAX_SID_CTX_LENGTH)-1] of byte;
     psk_identity_hint : pbyte;
     psk_identity : pbyte;
     not_resumable : cint;
     peer : Pointer;
     peer_type : cint;
     peer_chain:Pointer;
     verify_result : clong;
     references : cint;
     timeout : clong;
     time : clong;
     compress_meth : cuint;
     cipher : PSSL_CIPHER;
     cipher_id : culong;
     ciphers:Pointer;
     ex_data : Tcrypto_ex_data_st;
     prev : Pssl_session;
     next : Pssl_session;
     tlsext_hostname : pbyte;
     tlsext_ecpointformatlist_length : size_t;
     tlsext_ecpointformatlist : pbyte;
     tlsext_ellipticcurvelist_length : size_t;
     tlsext_ellipticcurvelist : pbyte;
     tlsext_tick : pbyte;
     tlsext_ticklen : size_t;
     tlsext_tick_lifetime_hint : culong;
     srp_username : pbyte;
     flags : uint32;
     lock : PCRYPTO_RWLOCK;
   end;
 PPSSL_SESSION=^PSSL_SESSION;

 Pstack_st_X509 = ^Tstack_st_X509;
 Tstack_st_X509 = record
     {undefined structure}
   end;
 PX509=Pstack_st_X509;
 PPX509=^PX509;

 PEVP_PKEY=Pointer;
 PPEVP_PKEY=^PEVP_PKEY;

 PSSL_CTX=^ssl_ctx_st;

 Tssl_ctx_new_session_cb   =function  (ssl:Pssl; sess:PSSL_SESSION):cint;cdecl;
 Tssl_ctx_remove_session_cb=procedure (ctx:Pssl_ctx; sess:PSSL_SESSION);cdecl;
 Tssl_ctx_get_session_cb   =function  (ssl:Pssl; data:pbyte; len:cint; copy:pcint):PSSL_SESSION;cdecl;
 Tssl_ctx_info_cb          =procedure (ssl:PSSL; _type:cint; val:cint);cdecl;
 Tssl_ctx_client_cert_cb   =function  (ssl:PSSL; x509:PPX509; pkey:PPEVP_PKEY):cint;cdecl;
 Tssl_ctx_gen_cookie_cb    =function  (ssl:PSSL; cookie:pbyte; cookie_len:pcuint):cint;cdecl;
 Tssl_ctx_verify_cookie_cb =function  (ssl:PSSL; cookie:pbyte; cookie_len:cuint):cint;cdecl;
 Tnext_proto_advertised_cb =function  (ssl:PSSL;_out:Ppbyte; outlen:pcuint; arg:pointer):cint;cdecl;
 Tnext_proto_select_cb     =function  (ssl:PSSL;_out:Ppbyte; outlen:pbyte;_in:pbyte; inlen:cuint; arg:pointer):cint;cdecl;

 ssl_ctx_st = record
  method : PSSL_METHOD;
  cipher_list:Pointer;
  // same as above but sorted for lookup */
  cipher_list_by_id:Pointer;
  cert_store : Pointer;
  sessions:Pointer;
   {
   * Most session-ids that will be cached, default is
   * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
   }
  session_cache_size : culong;
  session_cache_head : Pointer;
  session_cache_tail : Pointer;
  session_cache_mode : uint32;
  session_timeout : clong;
  new_session_cb : Tssl_ctx_new_session_cb;
  remove_session_cb :Tssl_ctx_remove_session_cb;
  get_session_cb : Tssl_ctx_get_session_cb;
  stats : record
      sess_connect : cint;
      sess_connect_renegotiate : cint;
      sess_connect_good : cint;
      sess_accept : cint;
      sess_accept_renegotiate : cint;
      sess_accept_good : cint;
      sess_miss : cint;
      sess_timeout : cint;
      sess_cache_full : cint;
      sess_hit : cint;
      sess_cb_hit : cint;
    end;
  //---------------
 end;

 Tssl_method_st = record
     version : cint;
     flags : cunsigned;
     mask : culong;
     ssl_new : function  (s:PSSL):cint;cdecl;
     ssl_clear : procedure (s:PSSL);cdecl;
     ssl_free : procedure (s:PSSL);cdecl;
     ssl_accept : function  (s:PSSL):cint;cdecl;
     ssl_connect : function  (s:PSSL):cint;cdecl;
     ssl_read : function  (s:PSSL; buf:pointer; len:cint):cint;cdecl;
     ssl_peek : function  (s:PSSL; buf:pointer; len:cint):cint;cdecl;
     ssl_write : function  (s:PSSL; buf:pointer; len:cint):cint;cdecl;
     ssl_shutdown : function  (s:PSSL):cint;cdecl;
     ssl_renegotiate : function  (s:PSSL):cint;cdecl;
     ssl_renegotiate_check : function  (s:PSSL):cint;cdecl;
     ssl_read_bytes : function  (s:PSSL; _type:cint; recvd_type:pcint; buf:pbyte; len:cint;
                  peek:cint):cint;cdecl;
     ssl_write_bytes : function  (s:PSSL; _type:cint; buf_:pointer; len:cint):cint;cdecl;
     ssl_dispatch_alert : function  (s:PSSL):cint;cdecl;
     ssl_ctrl : function  (s:PSSL; cmd:cint; larg:clong; parg:pointer):clong;cdecl;
     ssl_ctx_ctrl : function  (ctx:PSSL_CTX; cmd:cint; larg:clong; parg:pointer):clong;cdecl;
     get_cipher_by_char : function  (ptr:pbyte):PSSL_CIPHER;cdecl;
     put_cipher_by_char : function  (cipher:PSSL_CIPHER; ptr:pbyte):cint;cdecl;
     ssl_pending : function  (s:PSSL):cint;cdecl;
     num_ciphers : function  :cint;cdecl;
     get_cipher : function  (ncipher:cunsigned):PSSL_CIPHER;cdecl;
     get_timeout : function  :clong;cdecl;
     ssl3_enc : Pointer;
     ssl_version : function  :cint;cdecl;
     ssl_callback_ctrl : function  (s:PSSL; cb_id:cint; fp:Tcprocedure ):clong;cdecl;
     ssl_ctx_callback_ctrl : function  (s:PSSL_CTX; cb_id:cint; fp:Tcprocedure ):clong;cdecl;
   end;

  Topenssl_ssl_test_functions=record
   p_ssl_init_wbio_buffer : function  (s:PSSL):cint;cdecl;
   p_ssl3_setup_buffers   : function  (s:PSSL):cint;cdecl;
   {$IFNDEF OPENSSL_NO_HEARTBEATS}
    p_dtls1_process_heartbeat   : function  (s:PSSL;P:PByte;length:cuint):cint;cdecl;
   {$ENDIF}
  end;
  Popenssl_ssl_test_functions=^Topenssl_ssl_test_functions;

  Pconf= ^Tconf_st;
  Tconf_st = record
      {undefined structure}
  end;

   PASN1_OBJECT=Pointer;
   PPASN1_OBJECT=^PASN1_OBJECT;
   TASN1_TYPE=record end;
   PASN1_TYPE=^TASN1_TYPE;
   PPASN1_TYPE=^PASN1_TYPE;
   PASN1_BIT_STRING=Pointer;
   PPASN1_BIT_STRING=^PASN1_BIT_STRING;
   PASN1_BMPSTRING=Pointer;
   PPASN1_BMPSTRING=^PASN1_BMPSTRING;
   PASN1_PRINTABLESTRING=Pointer;
   PPASN1_PRINTABLESTRING=^PASN1_PRINTABLESTRING;
   PASN1_T61STRING=Pointer;
   PPASN1_T61STRING=^PASN1_T61STRING;
   PASN1_IA5STRING=Pointer;
   PPASN1_IA5STRING=^PASN1_IA5STRING;
   Pd2i_of_void=Pointer;
   PASN1_VALUE=Pointer;
   PPASN1_VALUE=^PASN1_VALUE;
   PX509V3_CTX=Pointer;
   PASN1_PCTX=Pointer;
   PASN1_SCTX=Pointer;
   PASN1_TEMPLATE=Pointer;
   PEVP_MD=Pointer;
   PEVP_MD_CTX=Pointer;
   PEVP_CIPHER=Pointer;
   PEVP_CIPHER_CTX=Pointer;
   PEVP_PKEY_CTX=Pointer;
   PPEVP_PKEY_CTX=^PEVP_PKEY_CTX;
   PENGINE=Pointer;
   PPENGINE=^PENGINE;
   PEVP_ENCODE_CTX=Pointer;
   PEVP_PBE_KEYGEN=Pointer;
   PPEVP_PBE_KEYGEN=^PEVP_PBE_KEYGEN;
   PEVP_PKEY_ASN1_METHOD=Pointer;
   PX509_PUBKEY=Pointer;
   PPX509_PUBKEY=^PX509_PUBKEY;
   PPKCS8_PRIV_KEY_INFO=Pointer;
   PPPKCS8_PRIV_KEY_INFO=^PPKCS8_PRIV_KEY_INFO;
   PEVP_PKEY_METHOD=Pointer;
   PBN_MONT_CTX=Pointer;
   PPBN_MONT_CTX=^PBN_MONT_CTX;
   PBN_CTX=Pointer;
   PEC_KEY=Pointer;
   PPEC_KEY=^PEC_KEY;
   PEC_KEY_METHOD=Pointer;
   PECDSA_SIG=Pointer;
   PPECDSA_SIG=^PECDSA_SIG;
   PRSA_METHOD=Pointer;
   PBN_BLINDING=Pointer;
   PDH_METHOD=Pointer;
   PDSA_SIG=Pointer;
   PPDSA_SIG=^PDSA_SIG;
   PDSA_METHOD=Pointer;
   PX509_PKEY=Pointer;
   PNETSCAPE_SPKAC=Pointer;
   PPNETSCAPE_SPKAC=^PNETSCAPE_SPKAC;
   PX509_LOOKUP_METHOD=Pointer;
   PX509_POLICY_TREE=Pointer;
   PPX509_POLICY_TREE=^PX509_POLICY_TREE;
   PX509_POLICY_LEVEL=Pointer;
   PX509_POLICY_NODE=Pointer;
   PSSL_DANE=Pointer;
   PPKCS7_SIGNED=Pointer;
   PPPKCS7_SIGNED=^PPKCS7_SIGNED;
   PX509_CRL_METHOD=Pointer;
   PX509_REQ=Pointer;
   PPX509_REQ=^PX509_REQ;
   POCSP_REQ_CTX=Pointer;
   PX509_SIG=Pointer;
   PPX509_SIG=^PX509_SIG;
   PX509_ALGORS=Pointer;
   PPX509_ALGORS=^PX509_ALGORS;
   PX509_REQ_INFO=Pointer;
   PPX509_REQ_INFO=^PX509_REQ_INFO;
   PX509_EXTENSIONS=Pointer;
   PPX509_EXTENSIONS=^PX509_EXTENSIONS;
   PX509_CINF=Pointer;
   PPX509_CINF=^PX509_CINF;
   PX509_CERT_AUX=Pointer;
   PPX509_CERT_AUX=^PX509_CERT_AUX;
   PX509_CRL_INFO=Pointer;
   PPX509_CRL_INFO=^PX509_CRL_INFO;
   PHMAC_CTX=Pointer;
   PASYNC_WAIT_CTX=Pointer;
   PASYNC_JOB=Pointer;
   PPASYNC_JOB=^PASYNC_JOB;
   PSSL_CONF_CTX=Pointer;
   PBN_RECP_CTX=Pointer;

   POPENSSL_STACK  = Pointer;//OPENSSL_STACK;

{$define HEADER_SSL_H}
{$define HEADER_E_OS2_H}
{$define OPENSSL_SYS_UNIX}

//const
  //OPENSSL_UNISTD_IO = OPENSSL_UNISTD;  
{$define OPENSSL_DECLARE_EXIT}
{$define OPENSSL_GLOBAL}
type
  ossl_ssize_t = ssize_t;
{$define __owur}
{$define ossl_inline}
{$define ossl_noreturn}
{$define HEADER_COMP_H}
{$define HEADER_CRYPTO_H}
{$define HEADER_STACK_H}
type
  TOPENSSL_sk_compfunc = function  (para1:pointer; para2:pointer):cint;cdecl;

  TOPENSSL_sk_freefunc = procedure (para1:pointer);cdecl;

  TOPENSSL_sk_copyfunc = function  (para1:pointer):pointer;cdecl;

function  OPENSSL_sk_num(para1:POPENSSL_STACK):cint;cdecl; external DLLUtilName;
function  OPENSSL_sk_value(para1:POPENSSL_STACK; para2:cint):pointer;cdecl; external DLLUtilName;
function  OPENSSL_sk_set(st:POPENSSL_STACK; i:cint; data:pointer):pointer;cdecl; external DLLUtilName;
function  OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK;cdecl; external DLLUtilName;
function  OPENSSL_sk_new_null:POPENSSL_STACK;cdecl; external DLLUtilName;
procedure OPENSSL_sk_free(para1:POPENSSL_STACK);cdecl; external DLLUtilName;
procedure OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc);cdecl; external DLLUtilName;
function  OPENSSL_sk_deep_copy(para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK;cdecl; external DLLUtilName;
function  OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:cint):cint;cdecl; external DLLUtilName;
function  OPENSSL_sk_delete(st:POPENSSL_STACK; loc:cint):pointer;cdecl; external DLLUtilName;
function  OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer;cdecl; external DLLUtilName;
function  OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer):cint;cdecl; external DLLUtilName;
function  OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer):cint;cdecl; external DLLUtilName;
function  OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer):cint;cdecl; external DLLUtilName;
function  OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer):cint;cdecl; external DLLUtilName;
function  OPENSSL_sk_shift(st:POPENSSL_STACK):pointer;cdecl; external DLLUtilName;
function  OPENSSL_sk_pop(st:POPENSSL_STACK):pointer;cdecl; external DLLUtilName;
procedure OPENSSL_sk_zero(st:POPENSSL_STACK);cdecl; external DLLUtilName;
function  OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc;cdecl; external DLLUtilName;
function  OPENSSL_sk_dup(st:POPENSSL_STACK):POPENSSL_STACK;cdecl; external DLLUtilName;
procedure OPENSSL_sk_sort(st:POPENSSL_STACK);cdecl; external DLLUtilName;
function  OPENSSL_sk_is_sorted(st:POPENSSL_STACK):cint;cdecl; external DLLUtilName;

{$define HEADER_SAFESTACK_H}

    type
      POPENSSL_STRING = ^TOPENSSL_STRING;
      TOPENSSL_STRING = pbyte;

      POPENSSL_CSTRING = ^TOPENSSL_CSTRING;
      TOPENSSL_CSTRING = pbyte;
      Pstack_st_OPENSSL_STRING = ^Tstack_st_OPENSSL_STRING;
      Tstack_st_OPENSSL_STRING = record
          {undefined structure}
        end;


      Tsk_OPENSSL_STRING_compfunc = function  (a:Ppbyte; b:Ppbyte):cint;cdecl;

      Tsk_OPENSSL_STRING_freefunc = procedure (a:pbyte);cdecl;

      Tsk_OPENSSL_STRING_copyfunc = function  (a:pbyte):pbyte;cdecl;

      Tsk_OPENSSL_CSTRING_compfunc = function  (a:Ppbyte; b:Ppbyte):cint;cdecl;

      Tsk_OPENSSL_CSTRING_freefunc = procedure (a:pbyte);cdecl;

      Tsk_OPENSSL_CSTRING_copyfunc = function  (a:pbyte):pbyte;cdecl;

      Pstack_st_OPENSSL_BLOCK = ^Tstack_st_OPENSSL_BLOCK;
      Tstack_st_OPENSSL_BLOCK = record
          {undefined structure}
        end;


      Tsk_OPENSSL_BLOCK_compfunc = function  (a:Ppointer; b:Ppointer):cint;cdecl;

      Tsk_OPENSSL_BLOCK_freefunc = procedure (a:pointer);cdecl;

      Tsk_OPENSSL_BLOCK_copyfunc = function  (a:pointer):pointer;cdecl;

    const
      OPENSSL_VERSION_NUMBER = $1010007f;      
      OPENSSL_VERSION_TEXT = 'OpenSSL 1.1.0g  2 Nov 2017';      
      SHLIB_VERSION_HISTORY = '';      
      SHLIB_VERSION_NUMBER = '1.1';      
{$define HEADER_OPENSSL_TYPES_H}    
    type
      PASN1_BOOLEAN = ^TASN1_BOOLEAN;
      TASN1_BOOLEAN = cint;

      PASN1_NULL = ^TASN1_NULL;
      TASN1_NULL = cint;

      Pdane = ^Tdane_st;
      Tdane_st = record
          {undefined structure}
        end;

      PBIGNUM=Pointer;
      PPBIGNUM=^PBIGNUM;
      PBN_GENCB=Pointer;

      Possl_intmax_t = ^Tossl_intmax_t;
      Tossl_intmax_t = clong;

      Possl_uintmax_t = ^Tossl_uintmax_t;
      Tossl_uintmax_t = culong;
{$define HEADER_SYMHACKS_H}    

    type
      PCRYPTO_dynlock = ^TCRYPTO_dynlock;
      TCRYPTO_dynlock = record
          dummy : cint;
        end;

function  CRYPTO_THREAD_lock_new:PCRYPTO_RWLOCK;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_read_lock(lock:PCRYPTO_RWLOCK):cint;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_write_lock(lock:PCRYPTO_RWLOCK):cint;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_unlock(lock:PCRYPTO_RWLOCK):cint;cdecl; external DLLUtilName;
procedure CRYPTO_THREAD_lock_free(lock:PCRYPTO_RWLOCK);cdecl; external DLLUtilName;
function  CRYPTO_atomic_add(val:pcint; amount:cint; ret:pcint; lock:PCRYPTO_RWLOCK):cint;cdecl; external DLLUtilName;

const
      CRYPTO_MEM_CHECK_OFF = $0;      
      CRYPTO_MEM_CHECK_ON = $1;      
      CRYPTO_MEM_CHECK_ENABLE = $2;      
      CRYPTO_MEM_CHECK_DISABLE = $3;



type
      Tsk_void_compfunc = function  (a:Ppointer; b:Ppointer):cint;cdecl;

      Tsk_void_freefunc = procedure (a:pointer);cdecl;

      Tsk_void_copyfunc = function  (a:pointer):pointer;cdecl;

    const
      CRYPTO_EX_INDEX_SSL     = 0;
      CRYPTO_EX_INDEX_SSL_CTX = 1;      
      CRYPTO_EX_INDEX_SSL_SESSION = 2;      
      CRYPTO_EX_INDEX_X509 = 3;      
      CRYPTO_EX_INDEX_X509_STORE = 4;      
      CRYPTO_EX_INDEX_X509_STORE_CTX = 5;      
      CRYPTO_EX_INDEX_DH = 6;      
      CRYPTO_EX_INDEX_DSA = 7;      
      CRYPTO_EX_INDEX_EC_KEY = 8;      
      CRYPTO_EX_INDEX_RSA = 9;      
      CRYPTO_EX_INDEX_ENGINE = 10;      
      CRYPTO_EX_INDEX_UI = 11;      
      CRYPTO_EX_INDEX_BIO = 12;      
      CRYPTO_EX_INDEX_APP = 13;      
      CRYPTO_EX_INDEX__COUNT = 14;      

    function  OPENSSL_malloc_init : cint;

function  CRYPTO_mem_ctrl(mode:cint):cint;cdecl; external DLLUtilName;

    function  OPENSSL_malloc(num : size_t) : Pointer;

    function  OPENSSL_zalloc(num : size_t) : Pointer;

    function  OPENSSL_realloc(addr:Pointer;num : size_t) : Pointer;

    function  OPENSSL_clear_realloc(addr:Pointer;old_num,num : size_t) : Pointer;

    Procedure OPENSSL_clear_free(addr:Pointer;num : size_t);

    Procedure OPENSSL_free(addr : Pointer);

    function  OPENSSL_memdup(str:Pointer;s : size_t) : Pointer;

    function  OPENSSL_strdup(str : pbyte) : pbyte;

    function  OPENSSL_strndup(str : pbyte;n : size_t) : pbyte;

    function  OPENSSL_secure_malloc(num : size_t) : Pointer;

    function  OPENSSL_secure_zalloc(num : size_t) : Pointer;

    Procedure OPENSSL_secure_free(addr : Pointer);

    Procedure OPENSSL_secure_clear_free(addr:Pointer;num : longint);

    function  OPENSSL_secure_actual_size(ptr : Pointer) : size_t;

function  OPENSSL_strlcpy(dst:pbyte; src:pbyte; siz:size_t):size_t;cdecl; external DLLUtilName;
function  OPENSSL_strlcat(dst:pbyte; src:pbyte; siz:size_t):size_t;cdecl; external DLLUtilName;
function  OPENSSL_strnlen(str:pbyte; maxlen:size_t):size_t;cdecl; external DLLUtilName;
function  OPENSSL_buf2hexstr(buffer:pbyte; len:clong):pbyte;cdecl; external DLLUtilName;
function  OPENSSL_hexstr2buf(str:pbyte; len:pclong):pbyte;cdecl; external DLLUtilName;
function  OPENSSL_hexchar2int(c:byte):cint;cdecl; external DLLUtilName;

    function  OPENSSL_MALLOC_MAX_NELEMS(SizeOf_type : longint) : longint;

function  OpenSSL_version_num:culong;cdecl; external DLLUtilName;
function  OpenSSL_version(_type:cint):pbyte;cdecl; external DLLUtilName;

    const
      _OPENSSL_VERSION = 0;      
      _OPENSSL_CFLAGS = 1;      
      _OPENSSL_BUILT_ON = 2;      
      _OPENSSL_PLATFORM = 3;      
      _OPENSSL_DIR = 4;      
      _OPENSSL_ENGINES_DIR = 5;      

function  OPENSSL_issetugid:cint;cdecl; external DLLUtilName;

    type
      TCRYPTO_EX_new  = Procedure(parent,ptr:Pointer;ad:PCRYPTO_EX_DATA;idx:cint;argl:clong;argp:Pointer);cdecl;
      TCRYPTO_EX_free = TCRYPTO_EX_new;
      TCRYPTO_EX_dup  = function(_to,from:PCRYPTO_EX_DATA;from_d:Pointer;idx:cint;argl:clong;argp:Pointer):cint;cdecl;

function  CRYPTO_get_ex_new_index(class_index:cint; argl:clong; argp:pointer; new_func:TCRYPTO_EX_new; dup_func:TCRYPTO_EX_dup;
               free_func:TCRYPTO_EX_free):cint;cdecl; external DLLUtilName;
function  CRYPTO_free_ex_index(class_index:cint; idx:cint):cint;cdecl; external DLLUtilName;
function  CRYPTO_new_ex_data(class_index:cint; obj:pointer; ad:PCRYPTO_EX_DATA):cint;cdecl; external DLLUtilName;
function  CRYPTO_dup_ex_data(class_index:cint; _to:PCRYPTO_EX_DATA; from:PCRYPTO_EX_DATA):cint;cdecl; external DLLUtilName;
procedure CRYPTO_free_ex_data(class_index:cint; obj:pointer; ad:PCRYPTO_EX_DATA);cdecl; external DLLUtilName;
function  CRYPTO_set_ex_data(ad:PCRYPTO_EX_DATA; idx:cint; val:pointer):cint;cdecl; external DLLUtilName;
function  CRYPTO_get_ex_data(ad:PCRYPTO_EX_DATA; idx:cint):pointer;cdecl; external DLLUtilName;

    const
      CRYPTO_LOCK = 1;      
      CRYPTO_UNLOCK = 2;      
      CRYPTO_READ = 4;      
      CRYPTO_WRITE = 8;

    type
      Pcrypto_threadid= ^Tcrypto_threadid_st;
      Tcrypto_threadid_st = record
          dummy : cint;
        end;

type
 Tmalloc_f =function  (num:size_t; buf:pbyte; line:cint):pointer; cdecl;
 Trealloc_f=function  (p:pointer; num:size_t; buf:pbyte; line:cint):pointer; cdecl;
 Tfree_f   =procedure (p:pointer; buf:pbyte; line:cint); cdecl;

function  CRYPTO_set_mem_functions(m:Tmalloc_f; r:Trealloc_f; f:Tfree_f):cint;cdecl; external DLLUtilName;
function  CRYPTO_set_mem_debug(flag:cint):cint;cdecl; external DLLUtilName;
procedure CRYPTO_get_mem_functions(var m:Tmalloc_f;var r:Trealloc_f;var f:Tfree_f);cdecl; external DLLUtilName;
function  CRYPTO_malloc(num:size_t; buf:pbyte; line:cint):pointer;cdecl; external DLLUtilName;
function  CRYPTO_zalloc(num:size_t; buf:pbyte; line:cint):pointer;cdecl; external DLLUtilName;
function  CRYPTO_memdup(str:pointer; siz:size_t; buf:pbyte; line:cint):pointer;cdecl; external DLLUtilName;
function  CRYPTO_strdup(str:pbyte; buf:pbyte; line:cint):pbyte;cdecl; external DLLUtilName;
function  CRYPTO_strndup(str:pbyte; s:size_t; buf:pbyte; line:cint):pbyte;cdecl; external DLLUtilName;
procedure CRYPTO_free(ptr:pointer; buf:pbyte; line:cint);cdecl; external DLLUtilName;
procedure CRYPTO_clear_free(ptr:pointer; num:size_t; buf:pbyte; line:cint);cdecl; external DLLUtilName;
function  CRYPTO_realloc(addr:pointer; num:size_t; buf:pbyte; line:cint):pointer;cdecl; external DLLUtilName;
function  CRYPTO_clear_realloc(addr:pointer; old_num:size_t; num:size_t; buf:pbyte; line:cint):pointer;cdecl; external DLLUtilName;
function  CRYPTO_secure_malloc_init(sz:size_t; minsize:cint):cint;cdecl; external DLLUtilName;
function  CRYPTO_secure_malloc_done:cint;cdecl; external DLLUtilName;
function  CRYPTO_secure_malloc(num:size_t; buf:pbyte; line:cint):pointer;cdecl; external DLLUtilName;
function  CRYPTO_secure_zalloc(num:size_t; buf:pbyte; line:cint):pointer;cdecl; external DLLUtilName;
procedure CRYPTO_secure_free(ptr:pointer; buf:pbyte; line:cint);cdecl; external DLLUtilName;
procedure CRYPTO_secure_clear_free(ptr:pointer; num:size_t; buf:pbyte; line:cint);cdecl; external DLLUtilName;
function  CRYPTO_secure_allocated(ptr:pointer):cint;cdecl; external DLLUtilName;
function  CRYPTO_secure_malloc_initialized:cint;cdecl; external DLLUtilName;
function  CRYPTO_secure_actual_size(ptr:pointer):size_t;cdecl; external DLLUtilName;
function  CRYPTO_secure_used:size_t;cdecl; external DLLUtilName;
procedure OPENSSL_cleanse(ptr:pointer; len:size_t);cdecl; external DLLUtilName;

function  OPENSSL_mem_debug_push(info : Pbyte) : cint;

    function  OPENSSL_mem_debug_pop : longint;    

function  CRYPTO_mem_debug_push(info:pbyte; buf:pbyte; line:cint):cint;cdecl; external DLLUtilName;
function  CRYPTO_mem_debug_pop:cint;cdecl; external DLLUtilName;
procedure CRYPTO_mem_debug_malloc(addr:pointer; num:size_t; flag:cint; buf:pbyte; line:cint);cdecl; external DLLUtilName;
procedure CRYPTO_mem_debug_realloc(addr1:pointer; addr2:pointer; num:size_t; flag:cint; buf:pbyte;
                line:cint);cdecl; external DLLUtilName;
procedure CRYPTO_mem_debug_free(addr:pointer; flag:cint; buf:pbyte; line:cint);cdecl; external DLLUtilName;
//function  CRYPTO_mem_leaks_fp(para1:PFILE):cint;cdecl; external DLLUtilName;
function  CRYPTO_mem_leaks(bio:PBIO):cint;cdecl; external DLLUtilName;
procedure OPENSSL_die(assertion:pbyte; buf:pbyte; line:cint);cdecl; external DLLUtilName;

Procedure  OpenSSLDie(f:PByte;l:cint;a:Pointer);

function  OPENSSL_isservice:cint;cdecl; external DLLUtilName;
function  FIPS_mode:cint;cdecl; external DLLUtilName;
function  FIPS_mode_set(r:cint):cint;cdecl; external DLLUtilName;
procedure OPENSSL_init;cdecl; external DLLUtilName;
function  OPENSSL_gmtime_adj(tm:Ptm; offset_day:cint; offset_sec:clong):cint;cdecl; external DLLUtilName;
function  OPENSSL_gmtime_diff(pday:pcint; psec:pcint; from:Ptm; _to:Ptm):cint;cdecl; external DLLUtilName;

const
      OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = $00000001;      
      OPENSSL_INIT_LOAD_CRYPTO_STRINGS = $00000002;      
      OPENSSL_INIT_ADD_ALL_CIPHERS = $00000004;      
      OPENSSL_INIT_ADD_ALL_DIGESTS = $00000008;      
      OPENSSL_INIT_NO_ADD_ALL_CIPHERS = $00000010;      
      OPENSSL_INIT_NO_ADD_ALL_DIGESTS = $00000020;      
      OPENSSL_INIT_LOAD_CONFIG = $00000040;      
      OPENSSL_INIT_NO_LOAD_CONFIG = $00000080;      
      OPENSSL_INIT_ASYNC = $00000100;      
      OPENSSL_INIT_ENGINE_RDRAND = $00000200;      
      OPENSSL_INIT_ENGINE_DYNAMIC = $00000400;      
      OPENSSL_INIT_ENGINE_OPENSSL = $00000800;      
      OPENSSL_INIT_ENGINE_CRYPTODEV = $00001000;      
      OPENSSL_INIT_ENGINE_CAPI = $00002000;      
      OPENSSL_INIT_ENGINE_PADLOCK = $00004000;      
      OPENSSL_INIT_ENGINE_AFALG = $00008000;      
      OPENSSL_INIT_ENGINE_ALL_BUILTIN = (((OPENSSL_INIT_ENGINE_RDRAND or OPENSSL_INIT_ENGINE_DYNAMIC) or OPENSSL_INIT_ENGINE_CRYPTODEV) or OPENSSL_INIT_ENGINE_CAPI) or OPENSSL_INIT_ENGINE_PADLOCK;      

procedure OPENSSL_cleanup;cdecl; external DLLUtilName;
function  OPENSSL_init_crypto(opts:uint64; settings:POPENSSL_INIT_SETTINGS):cint;cdecl; external DLLUtilName;
function  OPENSSL_atexit(handler:Tcprocedure ):cint;cdecl; external DLLUtilName;
procedure OPENSSL_thread_stop;cdecl; external DLLUtilName;
function  OPENSSL_INIT_new:POPENSSL_INIT_SETTINGS;cdecl; external DLLUtilName;
function  OPENSSL_INIT_set_config_appname(settings:POPENSSL_INIT_SETTINGS; config_file:pbyte):cint;cdecl; external DLLUtilName;
procedure OPENSSL_INIT_free(settings:POPENSSL_INIT_SETTINGS);cdecl; external DLLUtilName;

type
      PCRYPTO_ONCE = ^TCRYPTO_ONCE;
      TCRYPTO_ONCE = cuint;

      PCRYPTO_THREAD_LOCAL = ^TCRYPTO_THREAD_LOCAL;
      TCRYPTO_THREAD_LOCAL = cuint;

      PCRYPTO_THREAD_ID = ^TCRYPTO_THREAD_ID;
      TCRYPTO_THREAD_ID = cuint;

    const
      CRYPTO_ONCE_STATIC_INIT = 0;      

   type
    Tcleanup_f=procedure(para1:pointer); cdecl;

function  CRYPTO_THREAD_run_once(once:PCRYPTO_ONCE; init:Tcprocedure ):cint;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_init_local(key:PCRYPTO_THREAD_LOCAL; cleanup:Tcleanup_f):cint;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_get_local(key:PCRYPTO_THREAD_LOCAL):pointer;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_set_local(key:PCRYPTO_THREAD_LOCAL; val:pointer):cint;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_cleanup_local(key:PCRYPTO_THREAD_LOCAL):cint;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_get_current_id:TCRYPTO_THREAD_ID;cdecl; external DLLUtilName;
function  CRYPTO_THREAD_compare_id(a:TCRYPTO_THREAD_ID; b:TCRYPTO_THREAD_ID):cint;cdecl; external DLLUtilName;

   function  ERR_load_CRYPTO_strings:cint;

const
      CRYPTO_F_CRYPTO_DUP_EX_DATA = 110;      
      CRYPTO_F_CRYPTO_FREE_EX_DATA = 111;      
      CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 100;      
      CRYPTO_F_CRYPTO_MEMDUP = 115;      
      CRYPTO_F_CRYPTO_NEW_EX_DATA = 112;      
      CRYPTO_F_CRYPTO_SET_EX_DATA = 102;      
      CRYPTO_F_FIPS_MODE_SET = 109;      
      CRYPTO_F_GET_AND_LOCK = 113;      
      CRYPTO_F_OPENSSL_BUF2HEXSTR = 117;      
      CRYPTO_F_OPENSSL_HEXSTR2BUF = 118;      
      CRYPTO_F_OPENSSL_INIT_CRYPTO = 116;      
      CRYPTO_R_FIPS_MODE_NOT_SUPPORTED = 101;      
      CRYPTO_R_ILLEGAL_HEX_DIGIT = 102;      
      CRYPTO_R_ODD_NUMBER_OF_DIGITS = 103;      

    type
      PCOMP_METHOD = ^Tcomp_method_st;
      PCOMP_CTX = ^Tcomp_ctx_st;

      Tcomp_method_st = record
          _type : cint;
          name : pchar;
          init     : function  (ctx:PCOMP_CTX):cint;cdecl;
          finish   : procedure (ctx:PCOMP_CTX);cdecl;
          compress : function  (ctx:PCOMP_CTX; _out:pbyte; olen:cuint; _in:pbyte; ilen:cuint):cint;cdecl;
          expand   : function  (ctx:PCOMP_CTX; _out:pbyte; olen:cuint; _in:pbyte; ilen:cuint):cint;cdecl;
        end;

      Tcomp_ctx_st = record
          meth : PCOMP_METHOD;
          compress_in : culong;
          compress_out : culong;
          expand_in : culong;
          expand_out : culong;
          data : pointer;
        end;

function  COMP_CTX_new(meth:PCOMP_METHOD):PCOMP_CTX;cdecl; external DLLUtilName;
function  COMP_CTX_get_method(ctx:PCOMP_CTX):PCOMP_METHOD;cdecl; external DLLUtilName;
function  COMP_CTX_get_type(comp:PCOMP_CTX):cint;cdecl; external DLLUtilName;
function  COMP_get_type(meth:PCOMP_METHOD):cint;cdecl; external DLLUtilName;
function  COMP_get_name(meth:PCOMP_METHOD):pbyte;cdecl; external DLLUtilName;
procedure COMP_CTX_free(ctx:PCOMP_CTX);cdecl; external DLLUtilName;
function  COMP_compress_block(ctx:PCOMP_CTX; _out:pbyte; olen:cint; _in:pbyte; ilen:cint):cint;cdecl; external DLLUtilName;
function  COMP_expand_block(ctx:PCOMP_CTX; _out:pbyte; olen:cint; _in:pbyte; ilen:cint):cint;cdecl; external DLLUtilName;
function  COMP_zlib:PCOMP_METHOD;cdecl; external DLLUtilName;
function  ERR_load_COMP_strings:cint;cdecl; external DLLUtilName;

const
      COMP_F_BIO_ZLIB_FLUSH = 99;      
      COMP_F_BIO_ZLIB_NEW = 100;      
      COMP_F_BIO_ZLIB_READ = 101;      
      COMP_F_BIO_ZLIB_WRITE = 102;      
      COMP_R_ZLIB_DEFLATE_ERROR = 99;      
      COMP_R_ZLIB_INFLATE_ERROR = 100;      
      COMP_R_ZLIB_NOT_SUPPORTED = 101;      
{$define HEADER_BIO_H}    
      BIO_TYPE_DESCRIPTOR = $0100;      
      BIO_TYPE_FILTER = $0200;      
      BIO_TYPE_SOURCE_SINK = $0400;      
      BIO_TYPE_NONE = 0;      
      BIO_TYPE_MEM = 1 or BIO_TYPE_SOURCE_SINK;      
      BIO_TYPE_FILE = 2 or BIO_TYPE_SOURCE_SINK;      
      BIO_TYPE_FD = (4 or BIO_TYPE_SOURCE_SINK) or BIO_TYPE_DESCRIPTOR;      
      BIO_TYPE_SOCKET = (5 or BIO_TYPE_SOURCE_SINK) or BIO_TYPE_DESCRIPTOR;      
      BIO_TYPE_NULL = 6 or BIO_TYPE_SOURCE_SINK;      
      BIO_TYPE_SSL = 7 or BIO_TYPE_FILTER;      
      BIO_TYPE_MD = 8 or BIO_TYPE_FILTER;      
      BIO_TYPE_BUFFER = 9 or BIO_TYPE_FILTER;      
      BIO_TYPE_CIPHER = 10 or BIO_TYPE_FILTER;      
      BIO_TYPE_BASE64 = 11 or BIO_TYPE_FILTER;      
      BIO_TYPE_CONNECT = (12 or BIO_TYPE_SOURCE_SINK) or BIO_TYPE_DESCRIPTOR;      
      BIO_TYPE_ACCEPT = (13 or BIO_TYPE_SOURCE_SINK) or BIO_TYPE_DESCRIPTOR;      
      BIO_TYPE_NBIO_TEST = 16 or BIO_TYPE_FILTER;      
      BIO_TYPE_NULL_FILTER = 17 or BIO_TYPE_FILTER;      
      BIO_TYPE_BIO = 19 or BIO_TYPE_SOURCE_SINK;      
      BIO_TYPE_LINEBUFFER = 20 or BIO_TYPE_FILTER;      
      BIO_TYPE_DGRAM = (21 or BIO_TYPE_SOURCE_SINK) or BIO_TYPE_DESCRIPTOR;      
      BIO_TYPE_ASN1 = 22 or BIO_TYPE_FILTER;      
      BIO_TYPE_COMP = 23 or BIO_TYPE_FILTER;      
      BIO_TYPE_DGRAM_SCTP = (24 or BIO_TYPE_SOURCE_SINK) or BIO_TYPE_DESCRIPTOR;      
      BIO_TYPE_START = 128;      
      BIO_NOCLOSE = $00;      
      BIO_CLOSE = $01;      
      BIO_CTRL_RESET = 1;      
      BIO_CTRL_EOF = 2;      
      BIO_CTRL_INFO = 3;      
      BIO_CTRL_SET = 4;      
      BIO_CTRL_GET = 5;      
      BIO_CTRL_PUSH = 6;      
      BIO_CTRL_POP = 7;      
      BIO_CTRL_GET_CLOSE = 8;      
      BIO_CTRL_SET_CLOSE = 9;      
      _BIO_CTRL_PENDING = 10;      
      BIO_CTRL_FLUSH = 11;      
      BIO_CTRL_DUP = 12;      
      _BIO_CTRL_WPENDING = 13;      
      BIO_CTRL_SET_CALLBACK = 14;      
      BIO_CTRL_GET_CALLBACK = 15;      
      BIO_CTRL_SET_FILENAME = 30;      
      _BIO_CTRL_DGRAM_CONNECT = 31;      
      BIO_CTRL_DGRAM_SET_CONNECTED = 32;      
      BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33;      
      BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34;      
      BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35;      
      BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36;      
      BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37;      
      BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38;      
      BIO_CTRL_DGRAM_MTU_DISCOVER = 39;      
      BIO_CTRL_DGRAM_QUERY_MTU = 40;      
      BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;      
      BIO_CTRL_DGRAM_GET_MTU = 41;      
      BIO_CTRL_DGRAM_SET_MTU = 42;      
      BIO_CTRL_DGRAM_MTU_EXCEEDED = 43;      
      BIO_CTRL_DGRAM_GET_PEER = 46;      
      BIO_CTRL_DGRAM_SET_PEER = 44;      
      BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;      
      BIO_CTRL_DGRAM_SET_DONT_FRAG = 48;      
      BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49;      
      BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE = 50;      
      BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY = 51;      
      BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY = 52;      
      BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD = 53;      
      BIO_CTRL_DGRAM_SCTP_GET_SNDINFO = 60;      
      BIO_CTRL_DGRAM_SCTP_SET_SNDINFO = 61;      
      BIO_CTRL_DGRAM_SCTP_GET_RCVINFO = 62;      
      BIO_CTRL_DGRAM_SCTP_SET_RCVINFO = 63;      
      BIO_CTRL_DGRAM_SCTP_GET_PRINFO = 64;      
      BIO_CTRL_DGRAM_SCTP_SET_PRINFO = 65;      
      BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN = 70;      
      BIO_CTRL_DGRAM_SET_PEEK_MODE = 71;      
      BIO_FP_READ = $02;      
      BIO_FP_WRITE = $04;      
      BIO_FP_APPEND = $08;      
      BIO_FP_TEXT = $10;      
      BIO_FLAGS_READ = $01;      
      BIO_FLAGS_WRITE = $02;      
      BIO_FLAGS_IO_SPECIAL = $04;      
      BIO_FLAGS_RWS = (BIO_FLAGS_READ or BIO_FLAGS_WRITE) or BIO_FLAGS_IO_SPECIAL;      
      BIO_FLAGS_SHOULD_RETRY = $08;      
      BIO_FLAGS_UPLINK = 0;      
      BIO_FLAGS_BASE64_NO_NL = $100;      
      BIO_FLAGS_MEM_RDONLY = $200;      
      BIO_FLAGS_NONCLEAR_RST = $400;

    type
      PBIO_ADDR = ^Tbio_addr_st;
      Tbio_addr_st=record
       //union bio_addr_st {
       //    struct sockaddr sa;
       //# ifdef AF_INET6
       //    struct sockaddr_in6 s_in6;
       //# endif
       //    struct sockaddr_in s_in;
       //# ifdef AF_UNIX
       //    struct sockaddr_un s_un;
       //# endif
       //};
      end;

      PPBIO_ADDRINFO=^PBIO_ADDRINFO;
      PBIO_ADDRINFO=^Tbio_addrinfo_st;
      Tbio_addrinfo_st=record
       //int bai_family;
       //int bai_socktype;
       //int bai_protocol;
       //size_t bai_addrlen;
       //struct sockaddr *bai_addr;
       //struct bio_addrinfo_st *bai_next;
      end;

function  BIO_get_new_index:cint;cdecl; external DLLUtilName;
procedure BIO_set_flags(b:PBIO; flags:cint);cdecl; external DLLUtilName;
function  BIO_test_flags(b:PBIO; flags:cint):cint;cdecl; external DLLUtilName;
procedure BIO_clear_flags(b:PBIO; flags:cint);cdecl; external DLLUtilName;

    function  BIO_get_flags(b : PBIO) : cint;

    Procedure BIO_set_retry_special(b : PBIO);

    Procedure BIO_set_retry_read(b : PBIO);

    Procedure BIO_set_retry_write(b : PBIO);

    Procedure BIO_clear_retry_flags(b : PBIO);

    function  BIO_get_retry_flags(b : PBIO) : cint;

    function  BIO_should_read(a : PBIO) : cint;

    function  BIO_should_write(a : PBIO) : cint;

    function  BIO_should_io_special(a : PBIO) : cint;

    function  BIO_retry_type(a : PBIO) : cint;

    function  BIO_should_retry(a : PBIO) : cint;

    const
      BIO_RR_SSL_X509_LOOKUP = $01;
      BIO_RR_CONNECT = $02;
      BIO_RR_ACCEPT = $03;
      BIO_CB_FREE = $01;
      BIO_CB_READ = $02;
      BIO_CB_WRITE = $03;
      BIO_CB_PUTS = $04;
      BIO_CB_GETS = $05;
      BIO_CB_CTRL = $06;
      BIO_CB_RETURN = $80;

function  BIO_get_callback(b:PBIO):TBIO_callback_fn;cdecl; external DLLUtilName;
procedure BIO_set_callback(b:PBIO; callback:TBIO_callback_fn);cdecl; external DLLUtilName;
function  BIO_get_callback_arg(b:PBIO):pbyte;cdecl; external DLLUtilName;
procedure BIO_set_callback_arg(b:PBIO; arg:pbyte);cdecl; external DLLUtilName;

function  BIO_get_callback_ex(b:PBIO):TBIO_callback_fn_ex;cdecl; external DLLUtilName;
procedure BIO_set_callback_ex(b:PBIO; callback:TBIO_callback_fn_ex);cdecl; external DLLUtilName;

function  BIO_method_name(b:PBIO):pbyte;cdecl; external DLLUtilName;
function  BIO_method_type(b:PBIO):cint;cdecl; external DLLUtilName;

    type
      Pstack_st_BIO = ^Tstack_st_BIO;
      Tstack_st_BIO = record
          {undefined structure}
        end;


      Tsk_BIO_compfunc = function  (a:PPBIO; b:PPBIO):cint;cdecl;

      Tsk_BIO_freefunc = procedure (a:PBIO);cdecl;

      Psk_BIO_copyfunc = ^Tsk_BIO_copyfunc;
      Tsk_BIO_copyfunc = function  (a:PBIO):PBIO;cdecl;
      Pbio_dgram_sctp_sndinfo = ^Tbio_dgram_sctp_sndinfo;
      Tbio_dgram_sctp_sndinfo = record
          snd_sid : uint16;
          snd_flags : uint16;
          snd_ppid : uint32;
          snd_context : uint32;
        end;

      Pbio_dgram_sctp_rcvinfo = ^Tbio_dgram_sctp_rcvinfo;
      Tbio_dgram_sctp_rcvinfo = record
          rcv_sid : uint16;
          rcv_ssn : uint16;
          rcv_flags : uint16;
          rcv_ppid : uint32;
          rcv_tsn : uint32;
          rcv_cumtsn : uint32;
          rcv_context : uint32;
        end;

      Pbio_dgram_sctp_prinfo = ^Tbio_dgram_sctp_prinfo;
      Tbio_dgram_sctp_prinfo = record
          pr_policy : uint16;
          pr_value : uint32;
        end;

     Tbio_callback_ctrl_func=procedure (para1:PBIO; para2:cint; para3:pbyte; para4:cint; para5:clong;
                               para6:clong); cdecl;

    const
      BIO_C_SET_CONNECT = 100;      
      BIO_C_DO_STATE_MACHINE = 101;      
      BIO_C_SET_NBIO = 102;      
      BIO_C_SET_FD = 104;      
      BIO_C_GET_FD = 105;      
      BIO_C_SET_FILE_PTR = 106;      
      BIO_C_GET_FILE_PTR = 107;      
      BIO_C_SET_FILENAME = 108;      
      BIO_C_SET_SSL = 109;      
      BIO_C_GET_SSL = 110;      
      BIO_C_SET_MD = 111;      
      BIO_C_GET_MD = 112;      
      BIO_C_GET_CIPHER_STATUS = 113;      
      BIO_C_SET_BUF_MEM = 114;      
      BIO_C_GET_BUF_MEM_PTR = 115;      
      BIO_C_GET_BUFF_NUM_LINES = 116;      
      BIO_C_SET_BUFF_SIZE = 117;      
      BIO_C_SET_ACCEPT = 118;      
      BIO_C_SSL_MODE = 119;      
      BIO_C_GET_MD_CTX = 120;      
      BIO_C_SET_BUFF_READ_DATA = 122;      
      BIO_C_GET_CONNECT = 123;      
      BIO_C_GET_ACCEPT = 124;      
      BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125;      
      BIO_C_GET_SSL_NUM_RENEGOTIATES = 126;      
      BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;      
      BIO_C_FILE_SEEK = 128;      
      BIO_C_GET_CIPHER_CTX = 129;      
      BIO_C_SET_BUF_MEM_EOF_RETURN = 130;      
      BIO_C_SET_BIND_MODE = 131;      
      BIO_C_GET_BIND_MODE = 132;      
      BIO_C_FILE_TELL = 133;      
      BIO_C_GET_SOCKS = 134;      
      BIO_C_SET_SOCKS = 135;      
      BIO_C_SET_WRITE_BUF_SIZE = 136;      
      BIO_C_GET_WRITE_BUF_SIZE = 137;      
      BIO_C_MAKE_BIO_PAIR = 138;      
      BIO_C_DESTROY_BIO_PAIR = 139;      
      BIO_C_GET_WRITE_GUARANTEE = 140;      
      BIO_C_GET_READ_REQUEST = 141;      
      BIO_C_SHUTDOWN_WR = 142;      
      BIO_C_NREAD0 = 143;      
      BIO_C_NREAD = 144;      
      BIO_C_NWRITE0 = 145;      
      BIO_C_NWRITE = 146;      
      BIO_C_RESET_READ_REQUEST = 147;      
      BIO_C_SET_MD_CTX = 148;      
      BIO_C_SET_PREFIX = 149;      
      BIO_C_GET_PREFIX = 150;      
      BIO_C_SET_SUFFIX = 151;      
      BIO_C_GET_SUFFIX = 152;      
      BIO_C_SET_EX_ARG = 153;      
      BIO_C_GET_EX_ARG = 154;      
      BIO_C_SET_CONNECT_MODE = 155;      

    function  BIO_set_app_data(s : PBIO;arg : Pointer) : cint;

    function  BIO_get_app_data(s : PBIO) : Pointer;

    function  BIO_set_nbio(b : PBIO;n : clong) : clong;

    const
      BIO_FAMILY_IPV4 = 4;      
      BIO_FAMILY_IPV6 = 6;      
      BIO_FAMILY_IPANY = 256;      

    function  BIO_set_conn_hostname(b : PBIO;name : Pointer) : clong;

    function  BIO_set_conn_port(b : PBIO;port : Pointer) : clong;

    function  BIO_set_conn_address(b : PBIO;addr : Pointer) : clong;

    function  BIO_set_conn_ip_family(b : PBIO;f : cint) : clong;

    function  BIO_get_conn_hostname(b : PBIO) : Pointer;

    function  BIO_get_conn_port(b : PBIO) : Pointer;

    function  BIO_get_conn_address(b : PBIO) : Pointer;

    function  BIO_get_conn_ip_family(b : PBIO) : clong;

    function  BIO_set_conn_mode(b : PBIO;n : clong) : clong;

    function  BIO_set_accept_name(b : PBIO;name : Pointer) : clong;

    function  BIO_set_accept_port(b : PBIO;port : Pointer) : clong;

    function  BIO_get_accept_name(b : PBIO) : Pointer;

    function  BIO_get_accept_port(b : PBIO) : Pointer;

    function  BIO_get_peer_name(b : PBIO) : Pointer;

    function  BIO_get_peer_port(b : PBIO) : Pointer;

    function  BIO_set_nbio_accept(b : PBIO;n : Pointer) : clong;

    function  BIO_set_accept_bios(b : PBIO;bio : Pointer) : clong;

    function  BIO_set_accept_ip_family(b : PBIO;f : cint) : clong;

    function  BIO_get_accept_ip_family(b : PBIO) : clong;

    const
      BIO_SOCK_REUSEADDR = $01;
      BIO_SOCK_V6_ONLY = $02;
      BIO_SOCK_KEEPALIVE = $04;
      BIO_SOCK_NONBLOCK = $08;
      BIO_SOCK_NODELAY = $10;

      BIO_BIND_NORMAL = 0;      
      BIO_BIND_REUSEADDR = BIO_SOCK_REUSEADDR;      
      BIO_BIND_REUSEADDR_IF_UNUSED = BIO_SOCK_REUSEADDR;      

    function  BIO_set_bind_mode(b : PBIO;mode : clong) : clong;

    function  BIO_get_bind_mode(b : PBIO) : clong;

    function  BIO_do_connect(b : PBIO) : clong;

    function  BIO_do_accept(b : PBIO) : clong;

    function  BIO_do_handshake(b : PBIO) : clong;

    function  BIO_set_fd(b : PBIO;fd,c : clong) : clong;

    function  BIO_get_fd(b : PBIO;c : Pointer) : clong;

    function  BIO_set_fp(b : PBIO;fp : Pointer;c : clong) : clong;

    function  BIO_get_fp(b : PBIO;fpp : Pointer) : clong;

    function  BIO_seek(b : PBIO;ofs : clong) : clong;

    function  BIO_tell(b : PBIO) : clong;

    function  BIO_read_filename(b : PBIO;name : Pointer) : clong;

    function  BIO_write_filename(b : PBIO;name : Pointer) : clong;

    function  BIO_append_filename(b : PBIO;name : Pointer) : clong;

    function  BIO_rw_filename(b : PBIO;name : Pointer) : clong;

    function  BIO_set_ssl(b : PBIO;ssl:Pointer;c : clong) : clong;

    function  BIO_get_ssl(b : PBIO;sslp : Pointer) : clong;

    function  BIO_set_ssl_mode(b : PBIO;client : clong) : clong;

    function  BIO_set_ssl_renegotiate_bytes(b : PBIO;num : clong) : clong;

    function  BIO_get_num_renegotiates(b : PBIO) : clong;

    function  BIO_set_ssl_renegotiate_timeout(b : PBIO;seconds : clong) : clong;

    function  BIO_get_mem_data(b : PBIO;pp : Pointer) : clong;

    function  BIO_set_mem_buf(b : PBIO;bm : Pointer;c : clong) : clong;

    function  BIO_get_mem_ptr(b : PBIO;pp : Pointer) : clong;

    function  BIO_set_mem_eof_return(b : PBIO;v : clong) : clong;

    function  BIO_get_buffer_num_lines(b : PBIO) : clong;

    function  BIO_set_buffer_size(b : PBIO;size : clong) : clong;

    function  BIO_set_read_buffer_size(b : PBIO;size : clong) : clong;

    function  BIO_set_write_buffer_size(b : PBIO;size : clong) : clong;

    function  BIO_set_buffer_read_data(b : PBIO;buf:Pointer;num : clong) : clong;

    function  BIO_dup_state(b : PBIO;ret : Pointer) : clong;

    function  BIO_reset(b : PBIO) : clong;

    function  BIO_eof(b : PBIO) : clong;

    function  BIO_set_close(b : PBIO;c : clong) : clong;

    function  BIO_get_close(b : PBIO) : clong;

    function  BIO_pending(b : PBIO) : clong;

    function  BIO_wpending(b : PBIO) : clong;

function  BIO_ctrl_pending(b:PBIO):size_t;cdecl; external DLLUtilName;
function  BIO_ctrl_wpending(b:PBIO):size_t;cdecl; external DLLUtilName;

    function  BIO_flush(b : PBIO) : clong;

    function  BIO_get_info_callback(b : PBIO;cbp : Pointer) : clong;

    function  BIO_set_info_callback(b : PBIO;cb : Tbio_callback_ctrl_func) : clong;

    function  BIO_buffer_get_num_lines(b : PBIO) : clong;

    function  BIO_set_write_buf_size(b : PBIO;size : clong) : clong;

    function  BIO_get_write_buf_size(b : PBIO;size : clong) : clong;

    function  BIO_make_bio_pair(b1,b2 : PBIO) : clong;

    function  BIO_destroy_bio_pair(b : PBIO) : clong;

    function  BIO_shutdown_wr(b : PBIO) : clong;

    function  BIO_get_write_guarantee(b : PBIO) : clong;

    function  BIO_get_read_request(b : PBIO) : clong;

function  BIO_ctrl_get_write_guarantee(b:PBIO):size_t;cdecl; external DLLUtilName;
function  BIO_ctrl_get_read_request(b:PBIO):size_t;cdecl; external DLLUtilName;
function  BIO_ctrl_reset_read_request(b:PBIO):cint;cdecl; external DLLUtilName;

    function  BIO_ctrl_dgram_connect(b : PBIO;peer : Pointer) : clong;

    function  BIO_ctrl_set_connected(b : PBIO;peer : Pointer) : clong;

    function  BIO_dgram_recv_timedout(b : PBIO) : clong;

    function  BIO_dgram_send_timedout(b : PBIO) : clong;

    function  BIO_dgram_get_peer(b : PBIO;peer : Pointer) : clong;

    function  BIO_dgram_set_peer(b : PBIO;peer : Pointer) : clong;

    function  BIO_dgram_get_mtu_overhead(b : PBIO) : clong;

    function  BIO_get_ex_new_index(argl:clong; argp:pointer; new_func:TCRYPTO_EX_new; dup_func:TCRYPTO_EX_dup;free_func:TCRYPTO_EX_free) : cint;

function  BIO_set_ex_data(bio:PBIO; idx:cint; data:pointer):cint;cdecl; external DLLUtilName;
function  BIO_get_ex_data(bio:PBIO; idx:cint):pointer;cdecl; external DLLUtilName;
function  BIO_number_read(bio:PBIO):uint64;cdecl; external DLLUtilName;
function  BIO_number_written(bio:PBIO):uint64;cdecl; external DLLUtilName;
function  BIO_asn1_set_prefix(b:PBIO; prefix:Tasn1_ps_func; prefix_free:Tasn1_ps_func):cint;cdecl; external DLLUtilName;
function  BIO_asn1_get_prefix(b:PBIO; pprefix:PPasn1_ps_func; pprefix_free:PPasn1_ps_func):cint;cdecl; external DLLUtilName;
function  BIO_asn1_set_suffix(b:PBIO; suffix:Tasn1_ps_func; suffix_free:Tasn1_ps_func):cint;cdecl; external DLLUtilName;
function  BIO_asn1_get_suffix(b:PBIO; psuffix:PPasn1_ps_func; psuffix_free:PPasn1_ps_func):cint;cdecl; external DLLUtilName;
function  BIO_s_file:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_new_file(filename:pbyte; mode:pbyte):PBIO;cdecl; external DLLUtilName;
//function  BIO_new_fp(stream:PFILE; close_flag:cint):PBIO;cdecl; external DLLUtilName;
function  BIO_new(_type:PBIO_METHOD):PBIO;cdecl; external DLLUtilName;
function  BIO_free(a:PBIO):cint;cdecl; external DLLUtilName;
procedure BIO_set_data(a:PBIO; ptr:pointer);cdecl; external DLLUtilName;
function  BIO_get_data(a:PBIO):pointer;cdecl; external DLLUtilName;
procedure BIO_set_init(a:PBIO; init:cint);cdecl; external DLLUtilName;
function  BIO_get_init(a:PBIO):cint;cdecl; external DLLUtilName;
procedure BIO_set_shutdown(a:PBIO; shut:cint);cdecl; external DLLUtilName;
function  BIO_get_shutdown(a:PBIO):cint;cdecl; external DLLUtilName;
procedure BIO_vfree(a:PBIO);cdecl; external DLLUtilName;
function  BIO_up_ref(a:PBIO):cint;cdecl; external DLLUtilName;
function  BIO_read(b:PBIO; data:pointer; len:cint):cint;cdecl; external DLLUtilName;
function  BIO_gets(bp:PBIO; buf:pbyte; size:cint):cint;cdecl; external DLLUtilName;
function  BIO_write(b:PBIO; data:pointer; len:cint):cint;cdecl; external DLLUtilName;
function  BIO_puts(bp:PBIO; buf:pbyte):cint;cdecl; external DLLUtilName;
function  BIO_indent(b:PBIO; indent:cint; max:cint):cint;cdecl; external DLLUtilName;
function  BIO_ctrl(bp:PBIO; cmd:cint; larg:clong; parg:pointer):clong;cdecl; external DLLUtilName;

function  BIO_callback_ctrl(b:PBIO; cmd:cint; fp:Tbio_callback_ctrl_func):clong;cdecl; external DLLUtilName;
function  BIO_ptr_ctrl(bp:PBIO; cmd:cint; larg:clong):pointer;cdecl; external DLLUtilName;
function  BIO_int_ctrl(bp:PBIO; cmd:cint; larg:clong; iarg:cint):clong;cdecl; external DLLUtilName;
function  BIO_push(b:PBIO; append:PBIO):PBIO;cdecl; external DLLUtilName;
function  BIO_pop(b:PBIO):PBIO;cdecl; external DLLUtilName;
procedure BIO_free_all(a:PBIO);cdecl; external DLLUtilName;
function  BIO_find_type(b:PBIO; bio_type:cint):PBIO;cdecl; external DLLUtilName;
function  BIO_next(b:PBIO):PBIO;cdecl; external DLLUtilName;
procedure BIO_set_next(b:PBIO; next:PBIO);cdecl; external DLLUtilName;
function  BIO_get_retry_BIO(bio:PBIO; reason:pcint):PBIO;cdecl; external DLLUtilName;
function  BIO_get_retry_reason(bio:PBIO):cint;cdecl; external DLLUtilName;
procedure BIO_set_retry_reason(bio:PBIO; reason:cint);cdecl; external DLLUtilName;
function  BIO_dup_chain(_in:PBIO):PBIO;cdecl; external DLLUtilName;
function  BIO_nread0(bio:PBIO; buf:Ppbyte):cint;cdecl; external DLLUtilName;
function  BIO_nread(bio:PBIO; buf:Ppbyte; num:cint):cint;cdecl; external DLLUtilName;
function  BIO_nwrite0(bio:PBIO; buf:Ppbyte):cint;cdecl; external DLLUtilName;
function  BIO_nwrite(bio:PBIO; buf:Ppbyte; num:cint):cint;cdecl; external DLLUtilName;
function  BIO_debug_callback(bio:PBIO; cmd:cint; argp:pbyte; argi:cint; argl:clong; 
               ret:clong):clong;cdecl; external DLLUtilName;
function  BIO_s_mem:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_secmem:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_new_mem_buf(buf:pointer; len:cint):PBIO;cdecl; external DLLUtilName;
function  BIO_s_socket:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_connect:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_accept:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_fd:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_log:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_bio:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_null:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_f_null:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_f_buffer:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_f_linebuffer:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_f_nbio_test:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_s_datagram:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_dgram_non_fatal_error(error:cint):cint;cdecl; external DLLUtilName;
function  BIO_new_dgram(fd:cint; close_flag:cint):PBIO;cdecl; external DLLUtilName;
function  BIO_s_datagram_sctp:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_new_dgram_sctp(fd:cint; close_flag:cint):PBIO;cdecl; external DLLUtilName;
function  BIO_dgram_is_sctp(bio:PBIO):cint;cdecl; external DLLUtilName;

type
 Tbio_dgram_sctp_notification_func=procedure(bio:PBIO; context:pointer; buf:pointer); cdecl;
 TBIO_dump_cb=function  (data:pointer; len:size_t; u:pointer):cint;cdecl;

function  BIO_dgram_sctp_notification_cb(b:PBIO; handle_notifications:Tbio_dgram_sctp_notification_func; context:pointer):cint;cdecl; external DLLUtilName;
function  BIO_dgram_sctp_wait_for_dry(b:PBIO):cint;cdecl; external DLLUtilName;
function  BIO_dgram_sctp_msg_waiting(b:PBIO):cint;cdecl; external DLLUtilName;
function  BIO_sock_should_retry(i:cint):cint;cdecl; external DLLUtilName;
function  BIO_sock_non_fatal_error(error:cint):cint;cdecl; external DLLUtilName;
function  BIO_fd_should_retry(i:cint):cint;cdecl; external DLLUtilName;
function  BIO_fd_non_fatal_error(error:cint):cint;cdecl; external DLLUtilName;
function  BIO_dump_cb(cb:TBIO_dump_cb; u:pointer; s:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  BIO_dump_indent_cb(cb:TBIO_dump_cb; u:pointer; s:pbyte; len:cint; indent:cint):cint;cdecl; external DLLUtilName;
function  BIO_dump(b:PBIO; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  BIO_dump_indent(b:PBIO; bytes:pbyte; len:cint; indent:cint):cint;cdecl; external DLLUtilName;
//function  BIO_dump_fp(fp:PFILE; s:pbyte; len:cint):cint;cdecl; external DLLUtilName;
//function  BIO_dump_indent_fp(fp:PFILE; s:pbyte; len:cint; indent:cint):cint;cdecl; external DLLUtilName;
function  BIO_hex_string(_out:PBIO; indent:cint; width:cint; data:pbyte; datalen:cint):cint;cdecl; external DLLUtilName;
function  BIO_ADDR_new:PBIO_ADDR;cdecl; external DLLUtilName;
function  BIO_ADDR_rawmake(ap:PBIO_ADDR; family:cint; where:pointer; wherelen:size_t; port:cushort):cint;cdecl; external DLLUtilName;
procedure BIO_ADDR_free(para1:PBIO_ADDR);cdecl; external DLLUtilName;
procedure BIO_ADDR_clear(ap:PBIO_ADDR);cdecl; external DLLUtilName;
function  BIO_ADDR_family(ap:PBIO_ADDR):cint;cdecl; external DLLUtilName;
function  BIO_ADDR_rawaddress(ap:PBIO_ADDR; p:pointer; l:Psize_t):cint;cdecl; external DLLUtilName;
function  BIO_ADDR_rawport(ap:PBIO_ADDR):cushort;cdecl; external DLLUtilName;
function  BIO_ADDR_hostname_string(ap:PBIO_ADDR; numeric:cint):pbyte;cdecl; external DLLUtilName;
function  BIO_ADDR_service_string(ap:PBIO_ADDR; numeric:cint):pbyte;cdecl; external DLLUtilName;
function  BIO_ADDR_path_string(ap:PBIO_ADDR):pbyte;cdecl; external DLLUtilName;
function  BIO_ADDRINFO_next(bai:PBIO_ADDRINFO):PBIO_ADDRINFO;cdecl; external DLLUtilName;
function  BIO_ADDRINFO_family(bai:PBIO_ADDRINFO):cint;cdecl; external DLLUtilName;
function  BIO_ADDRINFO_socktype(bai:PBIO_ADDRINFO):cint;cdecl; external DLLUtilName;
function  BIO_ADDRINFO_protocol(bai:PBIO_ADDRINFO):cint;cdecl; external DLLUtilName;
function  BIO_ADDRINFO_address(bai:PBIO_ADDRINFO):PBIO_ADDR;cdecl; external DLLUtilName;
procedure BIO_ADDRINFO_free(bai:PBIO_ADDRINFO);cdecl; external DLLUtilName;

    type
      TBIO_hostserv_priorities =  Longint;

      Const
        BIO_PARSE_PRIO_HOST = 0;
        BIO_PARSE_PRIO_SERV = 1;


function  BIO_parse_hostserv(hostserv:pbyte; host:Ppbyte; service:Ppbyte; hostserv_prio:TBIO_hostserv_priorities):cint;cdecl; external DLLUtilName;

type
      TBIO_lookup_type =  Longint;

      Const
        BIO_LOOKUP_CLIENT = 0;
        BIO_LOOKUP_SERVER = 1;


function  BIO_lookup(host:pbyte; service:pbyte; lookup_type:TBIO_lookup_type; family:cint; socktype:cint; 
               res:PPBIO_ADDRINFO):cint;cdecl; external DLLUtilName;
function  BIO_sock_error(sock:cint):cint;cdecl; external DLLUtilName;
function  BIO_socket_ioctl(fd:cint; _type:clong; arg:pointer):cint;cdecl; external DLLUtilName;
function  BIO_socket_nbio(fd:cint; mode:cint):cint;cdecl; external DLLUtilName;
function  BIO_sock_init:cint;cdecl; external DLLUtilName;
function  BIO_set_tcp_ndelay(sock:cint; turn_on:cint):cint;cdecl; external DLLUtilName;

    type
      TBIO_sock_info_type =  Longint;

      Const
        BIO_SOCK_INFO_ADDRESS = 0;

      type
        PBIO_sock_info_u=^TBIO_sock_info_u;
        TBIO_sock_info_u=record
         addr:PBIO_ADDR;
        end;

        TBIO_sock_info=function(sock:cint;_type:cint;info:PBIO_sock_info_u):cint; cdecl;


function  BIO_sock_info(sock:cint; _type:TBIO_sock_info_type; info:PBIO_sock_info_u):cint;cdecl; external DLLUtilName;

function  BIO_socket(domain:cint; socktype:cint; protocol:cint; options:cint):cint;cdecl; external DLLUtilName;
function  BIO_connect(sock:cint; addr:PBIO_ADDR; options:cint):cint;cdecl; external DLLUtilName;
function  BIO_listen(sock:cint; addr:PBIO_ADDR; options:cint):cint;cdecl; external DLLUtilName;
function  BIO_accept_ex(accept_sock:cint; addr:PBIO_ADDR; options:cint):cint;cdecl; external DLLUtilName;
function  BIO_closesocket(sock:cint):cint;cdecl; external DLLUtilName;
function  BIO_new_socket(sock:cint; close_flag:cint):PBIO;cdecl; external DLLUtilName;
function  BIO_new_connect(host_port:pbyte):PBIO;cdecl; external DLLUtilName;
function  BIO_new_accept(host_port:pbyte):PBIO;cdecl; external DLLUtilName;
function  BIO_new_fd(fd:cint; close_flag:cint):PBIO;cdecl; external DLLUtilName;
function  BIO_new_bio_pair(bio1:PPBIO; writebuf1:size_t; bio2:PPBIO; writebuf2:size_t):cint;cdecl; external DLLUtilName;
procedure BIO_copy_next_retry(b:PBIO);cdecl; external DLLUtilName;
function  BIO_printf(bio:PBIO; format:pbyte; args:array of const):cint;cdecl; external DLLUtilName;
//function  BIO_vprintf(bio:PBIO; format:pbyte; args:Tva_list):cint;cdecl; external DLLUtilName;
function  BIO_snprintf(buf:pbyte; n:size_t; format:pbyte; args:array of const):cint;cdecl; external DLLUtilName;
//function  BIO_vsnprintf(buf:pbyte; n:size_t; format:pbyte; args:Tva_list):cint;cdecl; external DLLUtilName;
function  BIO_meth_new(_type:cint; name:PChar):PBIO_METHOD;cdecl; external DLLUtilName;
procedure BIO_meth_free(biom:PBIO_METHOD);cdecl; external DLLUtilName;
function  BIO_meth_get_write(biom:PBIO_METHOD):TBio_meth_bwrite; cdecl; external DLLUtilName;
function  BIO_meth_set_write(biom:PBIO_METHOD;write:TBio_meth_bwrite):cint; cdecl; external DLLUtilName;
function  BIO_meth_get_read(biom:PBIO_METHOD):TBio_meth_bread; cdecl; external DLLUtilName;
function  BIO_meth_set_read(biom:PBIO_METHOD; read:TBio_meth_bread):cint;cdecl; external DLLUtilName;
function  BIO_meth_get_puts(biom:PBIO_METHOD):TBio_meth_bputs cdecl; external DLLUtilName;
function  BIO_meth_set_puts(biom:PBIO_METHOD; puts:TBio_meth_bputs):cint;cdecl; external DLLUtilName;
function  BIO_meth_get_gets(biom:PBIO_METHOD):TBio_meth_bgets cdecl; external DLLUtilName;
function  BIO_meth_set_gets(biom:PBIO_METHOD; gets:TBio_meth_bgets):cint;cdecl; external DLLUtilName;
function  BIO_meth_get_ctrl(biom:PBIO_METHOD):TBio_meth_ctrl cdecl; external DLLUtilName;
function  BIO_meth_set_ctrl(biom:PBIO_METHOD; ctrl:TBio_meth_ctrl):cint;cdecl; external DLLUtilName;
function  BIO_meth_get_create(bion:PBIO_METHOD):TBio_meth_create cdecl; external DLLUtilName;
function  BIO_meth_set_create(biom:PBIO_METHOD; create:TBio_meth_create ):cint;cdecl; external DLLUtilName;
function  BIO_meth_get_destroy(biom:PBIO_METHOD):TBio_meth_destroy; cdecl; external DLLUtilName;
function  BIO_meth_set_destroy(biom:PBIO_METHOD; destroy:TBio_meth_destroy ):cint;cdecl; external DLLUtilName;
function  BIO_meth_get_callback_ctrl(biom:PBIO_METHOD):TBio_meth_callback_ctrl cdecl; external DLLUtilName;
function  BIO_meth_set_callback_ctrl(biom:PBIO_METHOD; callback_ctrl:TBio_meth_callback_ctrl):cint;cdecl; external DLLUtilName;
function  ERR_load_BIO_strings:cint;cdecl; external DLLUtilName;

    const
      BIO_F_ACPT_STATE = 100;      
      BIO_F_ADDR_STRINGS = 134;      
      BIO_F_BIO_ACCEPT = 101;      
      BIO_F_BIO_ACCEPT_EX = 137;      
      BIO_F_BIO_ADDR_NEW = 144;      
      BIO_F_BIO_CALLBACK_CTRL = 131;      
      BIO_F_BIO_CONNECT = 138;      
      BIO_F_BIO_CTRL = 103;      
      BIO_F_BIO_GETS = 104;      
      BIO_F_BIO_GET_HOST_IP = 106;      
      BIO_F_BIO_GET_NEW_INDEX = 102;      
      BIO_F_BIO_GET_PORT = 107;      
      BIO_F_BIO_LISTEN = 139;      
      BIO_F_BIO_LOOKUP = 135;      
      BIO_F_BIO_MAKE_PAIR = 121;      
      BIO_F_BIO_NEW = 108;      
      BIO_F_BIO_NEW_FILE = 109;      
      BIO_F_BIO_NEW_MEM_BUF = 126;      
      BIO_F_BIO_NREAD = 123;      
      BIO_F_BIO_NREAD0 = 124;      
      BIO_F_BIO_NWRITE = 125;      
      BIO_F_BIO_NWRITE0 = 122;      
      BIO_F_BIO_PARSE_HOSTSERV = 136;      
      BIO_F_BIO_PUTS = 110;      
      BIO_F_BIO_READ = 111;      
      BIO_F_BIO_SOCKET = 140;      
      BIO_F_BIO_SOCKET_NBIO = 142;      
      BIO_F_BIO_SOCK_INFO = 141;      
      BIO_F_BIO_SOCK_INIT = 112;      
      BIO_F_BIO_WRITE = 113;      
      BIO_F_BUFFER_CTRL = 114;      
      BIO_F_CONN_CTRL = 127;      
      BIO_F_CONN_STATE = 115;      
      BIO_F_DGRAM_SCTP_READ = 132;      
      BIO_F_DGRAM_SCTP_WRITE = 133;      
      BIO_F_FILE_CTRL = 116;      
      BIO_F_FILE_READ = 130;      
      BIO_F_LINEBUFFER_CTRL = 129;      
      BIO_F_MEM_WRITE = 117;      
      BIO_F_SSL_NEW = 118;      
      BIO_R_ACCEPT_ERROR = 100;      
      BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET = 141;      
      BIO_R_AMBIGUOUS_HOST_OR_SERVICE = 129;      
      BIO_R_BAD_FOPEN_MODE = 101;      
      BIO_R_BROKEN_PIPE = 124;      
      BIO_R_CONNECT_ERROR = 103;      
      BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET = 107;      
      BIO_R_GETSOCKNAME_ERROR = 132;      
      BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS = 133;      
      BIO_R_GETTING_SOCKTYPE = 134;      
      BIO_R_INVALID_ARGUMENT = 125;      
      BIO_R_INVALID_SOCKET = 135;      
      BIO_R_IN_USE = 123;      
      BIO_R_LISTEN_V6_ONLY = 136;      
      BIO_R_LOOKUP_RETURNED_NOTHING = 142;      
      BIO_R_MALFORMED_HOST_OR_SERVICE = 130;      
      BIO_R_NBIO_CONNECT_ERROR = 110;      
      BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED = 143;      
      BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED = 144;      
      BIO_R_NO_PORT_DEFINED = 113;      
      BIO_R_NO_SUCH_FILE = 128;      
      BIO_R_NULL_PARAMETER = 115;      
      BIO_R_UNABLE_TO_BIND_SOCKET = 117;      
      BIO_R_UNABLE_TO_CREATE_SOCKET = 118;      
      BIO_R_UNABLE_TO_KEEPALIVE = 137;      
      BIO_R_UNABLE_TO_LISTEN_SOCKET = 119;      
      BIO_R_UNABLE_TO_NODELAY = 138;      
      BIO_R_UNABLE_TO_REUSEADDR = 139;      
      BIO_R_UNAVAILABLE_IP_FAMILY = 145;      
      BIO_R_UNINITIALIZED = 120;      
      BIO_R_UNKNOWN_INFO_TYPE = 140;      
      BIO_R_UNSUPPORTED_IP_FAMILY = 146;      
      BIO_R_UNSUPPORTED_METHOD = 121;      
      BIO_R_UNSUPPORTED_PROTOCOL_FAMILY = 131;      
      BIO_R_WRITE_TO_READ_ONLY_BIO = 126;      
      BIO_R_WSASTARTUP = 122;      
{$define HEADER_X509_H}    
{$define HEADER_BUFFER_H}    

    function  BUF_strdup(s : pbyte) : pbyte;

    function  BUF_strndup(s:pbyte;size : size_t) : pbyte;

    function  BUF_memdup(data:Pointer;size : size_t) : Pointer;

    function  BUF_strlcpy(dst,src:PByte;size : size_t) : size_t;

    function  BUF_strlcat(dst,src:PByte;size : size_t) : size_t;

    function  BUF_strnlen(str:PByte;maxlen : size_t) : size_t;

    const
      BUF_MEM_FLAG_SECURE = $01;      

function  BUF_MEM_new:PBUF_MEM;cdecl; external DLLUtilName;
function  BUF_MEM_new_ex(flags:culong):PBUF_MEM;cdecl; external DLLUtilName;
procedure BUF_MEM_free(a:PBUF_MEM);cdecl; external DLLUtilName;
function  BUF_MEM_grow(str:PBUF_MEM; len:size_t):size_t;cdecl; external DLLUtilName;
function  BUF_MEM_grow_clean(str:PBUF_MEM; len:size_t):size_t;cdecl; external DLLUtilName;
procedure BUF_reverse(_out:pbyte; _in:pbyte; siz:size_t);cdecl; external DLLUtilName;
function  ERR_load_BUF_strings:cint;cdecl; external DLLUtilName;

    const
      BUF_F_BUF_MEM_GROW = 100;      
      BUF_F_BUF_MEM_GROW_CLEAN = 105;      
      BUF_F_BUF_MEM_NEW = 101;      
{$define HEADER_ENVELOPE_H}    
      EVP_MAX_MD_SIZE = 64;      
      EVP_MAX_KEY_LENGTH = 64;      
      EVP_MAX_IV_LENGTH = 16;      
      EVP_MAX_BLOCK_LENGTH = 32;      
      PKCS5_SALT_LEN = 8;      
      PKCS5_DEFAULT_ITER = 2048;      
{$define HEADER_OBJECTS_H}    
{$define USE_OBJ_MAC}
      NID_undef = 0;      
      OBJ_undef = 0;
      NID_itu_t = 645;      
      OBJ_itu_t = 0;      
      NID_ccitt = 404;      
      OBJ_ccitt = OBJ_itu_t;
      NID_iso = 181;      
      OBJ_iso = 1;
      NID_joint_iso_itu_t = 646;      
      OBJ_joint_iso_itu_t = 2;      
      NID_joint_iso_ccitt = 393;      
      OBJ_joint_iso_ccitt = OBJ_joint_iso_itu_t;
      NID_member_body = 182;
      NID_identified_organization = 676;
      NID_hmac_md5 = 780;
      NID_hmac_sha1 = 781;
      NID_certicom_arc = 677;
      NID_international_organizations = 647;
      NID_wap = 678;
      NID_wap_wsg = 679;
      NID_selected_attribute_types = 394;
      NID_clearance = 395;
      NID_ISO_US = 183;
      NID_X9_57 = 184;
      NID_X9cm = 185;
      NID_dsa = 116;
      NID_dsaWithSHA1 = 113;
      NID_ansi_X9_62 = 405;
      NID_X9_62_prime_field = 406;
      NID_X9_62_characteristic_two_field = 407;
      NID_X9_62_id_characteristic_two_basis = 680;
      NID_X9_62_onBasis = 681;
      NID_X9_62_tpBasis = 682;
      NID_X9_62_ppBasis = 683;
      NID_X9_62_id_ecPublicKey = 408;
      NID_X9_62_c2pnb163v1 = 684;
      NID_X9_62_c2pnb163v2 = 685;
      NID_X9_62_c2pnb163v3 = 686;
      NID_X9_62_c2pnb176v1 = 687;      
      NID_X9_62_c2tnb191v1 = 688;      
      NID_X9_62_c2tnb191v2 = 689;      
      NID_X9_62_c2tnb191v3 = 690;      
      NID_X9_62_c2onb191v4 = 691;      
      NID_X9_62_c2onb191v5 = 692;      
      NID_X9_62_c2pnb208w1 = 693;      
      NID_X9_62_c2tnb239v1 = 694;      
      NID_X9_62_c2tnb239v2 = 695;      
      NID_X9_62_c2tnb239v3 = 696;      
      NID_X9_62_c2onb239v4 = 697;      
      NID_X9_62_c2onb239v5 = 698;      
      NID_X9_62_c2pnb272w1 = 699;      
      NID_X9_62_c2pnb304w1 = 700;      
      NID_X9_62_c2tnb359v1 = 701;      
      NID_X9_62_c2pnb368w1 = 702;      
      NID_X9_62_c2tnb431r1 = 703;      
      NID_X9_62_prime192v1 = 409;      
      NID_X9_62_prime192v2 = 410;      
      NID_X9_62_prime192v3 = 411;      
      NID_X9_62_prime239v1 = 412;      
      NID_X9_62_prime239v2 = 413;      
      NID_X9_62_prime239v3 = 414;      
      NID_X9_62_prime256v1 = 415;      
      NID_ecdsa_with_SHA1 = 416;      
      NID_ecdsa_with_Recommended = 791;      
      NID_ecdsa_with_Specified = 792;      
      NID_ecdsa_with_SHA224 = 793;      
      NID_ecdsa_with_SHA256 = 794;      
      NID_ecdsa_with_SHA384 = 795;      
      NID_ecdsa_with_SHA512 = 796;      
      NID_secp112r1 = 704;      
      NID_secp112r2 = 705;      
      NID_secp128r1 = 706;      
      NID_secp128r2 = 707;      
      NID_secp160k1 = 708;      
      NID_secp160r1 = 709;      
      NID_secp160r2 = 710;      
      NID_secp192k1 = 711;      
      NID_secp224k1 = 712;      
      NID_secp224r1 = 713;      
      NID_secp256k1 = 714;      
      NID_secp384r1 = 715;      
      NID_secp521r1 = 716;      
      NID_sect113r1 = 717;      
      NID_sect113r2 = 718;      
      NID_sect131r1 = 719;      
      NID_sect131r2 = 720;      
      NID_sect163k1 = 721;      
      NID_sect163r1 = 722;      
      NID_sect163r2 = 723;      
      NID_sect193r1 = 724;      
      NID_sect193r2 = 725;      
      NID_sect233k1 = 726;      
      NID_sect233r1 = 727;      
      NID_sect239k1 = 728;      
      NID_sect283k1 = 729;      
      NID_sect283r1 = 730;      
      NID_sect409k1 = 731;      
      NID_sect409r1 = 732;      
      NID_sect571k1 = 733;      
      NID_sect571r1 = 734;      
      NID_wap_wsg_idm_ecid_wtls1 = 735;      
      NID_wap_wsg_idm_ecid_wtls3 = 736;      
      NID_wap_wsg_idm_ecid_wtls4 = 737;      
      NID_wap_wsg_idm_ecid_wtls5 = 738;      
      NID_wap_wsg_idm_ecid_wtls6 = 739;      
      NID_wap_wsg_idm_ecid_wtls7 = 740;      
      NID_wap_wsg_idm_ecid_wtls8 = 741;      
      NID_wap_wsg_idm_ecid_wtls9 = 742;      
      NID_wap_wsg_idm_ecid_wtls10 = 743;      
      NID_wap_wsg_idm_ecid_wtls11 = 744;      
      NID_wap_wsg_idm_ecid_wtls12 = 745;      
      NID_cast5_cbc = 108;      
      NID_cast5_ecb = 109;      
      NID_cast5_cfb64 = 110;      
      NID_cast5_ofb64 = 111;      
      NID_pbeWithMD5AndCast5_CBC = 112;      
      NID_id_PasswordBasedMAC = 782;      
      NID_id_DHBasedMac = 783;      
      NID_rsadsi = 1;      
      NID_pkcs = 2;      
      NID_pkcs1 = 186;      
      NID_rsaEncryption = 6;      
      NID_md2WithRSAEncryption = 7;      
      NID_md4WithRSAEncryption = 396;      
      NID_md5WithRSAEncryption = 8;      
      NID_sha1WithRSAEncryption = 65;      
      NID_rsaesOaep = 919;      
      NID_mgf1 = 911;      
      NID_pSpecified = 935;      
      NID_rsassaPss = 912;      
      NID_sha256WithRSAEncryption = 668;      
      NID_sha384WithRSAEncryption = 669;      
      NID_sha512WithRSAEncryption = 670;      
      NID_sha224WithRSAEncryption = 671;      
      NID_pkcs3 = 27;      
      NID_dhKeyAgreement = 28;      
      NID_pkcs5 = 187;      
      NID_pbeWithMD2AndDES_CBC = 9;      
      NID_pbeWithMD5AndDES_CBC = 10;      
      NID_pbeWithMD2AndRC2_CBC = 168;      
      NID_pbeWithMD5AndRC2_CBC = 169;      
      NID_pbeWithSHA1AndDES_CBC = 170;      
      NID_pbeWithSHA1AndRC2_CBC = 68;      
      NID_id_pbkdf2 = 69;      
      NID_pbes2 = 161;      
      NID_pbmac1 = 162;      
      NID_pkcs7 = 20;      
      NID_pkcs7_data = 21;      
      NID_pkcs7_signed = 22;      
      NID_pkcs7_enveloped = 23;      
      NID_pkcs7_signedAndEnveloped = 24;      
      NID_pkcs7_digest = 25;      
      NID_pkcs7_encrypted = 26;      
      NID_pkcs9 = 47;      
      NID_pkcs9_emailAddress = 48;      
      NID_pkcs9_unstructuredName = 49;      
      NID_pkcs9_contentType = 50;      
      NID_pkcs9_messageDigest = 51;      
      NID_pkcs9_signingTime = 52;      
      NID_pkcs9_countersignature = 53;      
      NID_pkcs9_challengePassword = 54;      
      NID_pkcs9_unstructuredAddress = 55;      
      NID_pkcs9_extCertAttributes = 56;      
      NID_ext_req = 172;      
      NID_SMIMECapabilities = 167;      
      NID_SMIME = 188;      
      NID_id_smime_mod = 189;      
      NID_id_smime_ct = 190;      
      NID_id_smime_aa = 191;      
      NID_id_smime_alg = 192;      
      NID_id_smime_cd = 193;      
      NID_id_smime_spq = 194;      
      NID_id_smime_cti = 195;      
      NID_id_smime_mod_cms = 196;      
      NID_id_smime_mod_ess = 197;      
      NID_id_smime_mod_oid = 198;      
      NID_id_smime_mod_msg_v3 = 199;      
      NID_id_smime_mod_ets_eSignature_88 = 200;      
      NID_id_smime_mod_ets_eSignature_97 = 201;      
      NID_id_smime_mod_ets_eSigPolicy_88 = 202;      
      NID_id_smime_mod_ets_eSigPolicy_97 = 203;      
      NID_id_smime_ct_receipt = 204;      
      NID_id_smime_ct_authData = 205;      
      NID_id_smime_ct_publishCert = 206;      
      NID_id_smime_ct_TSTInfo = 207;      
      NID_id_smime_ct_TDTInfo = 208;      
      NID_id_smime_ct_contentInfo = 209;      
      NID_id_smime_ct_DVCSRequestData = 210;      
      NID_id_smime_ct_DVCSResponseData = 211;      
      NID_id_smime_ct_compressedData = 786;      
      NID_id_smime_ct_contentCollection = 1058;      
      NID_id_smime_ct_authEnvelopedData = 1059;      
      NID_id_ct_asciiTextWithCRLF = 787;      
      NID_id_ct_xml = 1060;      
      NID_id_smime_aa_receiptRequest = 212;      
      NID_id_smime_aa_securityLabel = 213;      
      NID_id_smime_aa_mlExpandHistory = 214;      
      NID_id_smime_aa_contentHint = 215;      
      NID_id_smime_aa_msgSigDigest = 216;      
      NID_id_smime_aa_encapContentType = 217;      
      NID_id_smime_aa_contentIdentifier = 218;      
      NID_id_smime_aa_macValue = 219;      
      NID_id_smime_aa_equivalentLabels = 220;      
      NID_id_smime_aa_contentReference = 221;      
      NID_id_smime_aa_encrypKeyPref = 222;      
      NID_id_smime_aa_signingCertificate = 223;      
      NID_id_smime_aa_smimeEncryptCerts = 224;      
      NID_id_smime_aa_timeStampToken = 225;      
      NID_id_smime_aa_ets_sigPolicyId = 226;      
      NID_id_smime_aa_ets_commitmentType = 227;      
      NID_id_smime_aa_ets_signerLocation = 228;      
      NID_id_smime_aa_ets_signerAttr = 229;      
      NID_id_smime_aa_ets_otherSigCert = 230;      
      NID_id_smime_aa_ets_contentTimestamp = 231;      
      NID_id_smime_aa_ets_CertificateRefs = 232;      
      NID_id_smime_aa_ets_RevocationRefs = 233;      
      NID_id_smime_aa_ets_certValues = 234;      
      NID_id_smime_aa_ets_revocationValues = 235;      
      NID_id_smime_aa_ets_escTimeStamp = 236;      
      NID_id_smime_aa_ets_certCRLTimestamp = 237;      
      NID_id_smime_aa_ets_archiveTimeStamp = 238;      
      NID_id_smime_aa_signatureType = 239;      
      NID_id_smime_aa_dvcs_dvc = 240;      
      NID_id_smime_alg_ESDHwith3DES = 241;      
      NID_id_smime_alg_ESDHwithRC2 = 242;      
      NID_id_smime_alg_3DESwrap = 243;      
      NID_id_smime_alg_RC2wrap = 244;      
      NID_id_smime_alg_ESDH = 245;      
      NID_id_smime_alg_CMS3DESwrap = 246;      
      NID_id_smime_alg_CMSRC2wrap = 247;      
      NID_id_alg_PWRI_KEK = 893;      
      NID_id_smime_cd_ldap = 248;      
      NID_id_smime_spq_ets_sqt_uri = 249;      
      NID_id_smime_spq_ets_sqt_unotice = 250;      
      NID_id_smime_cti_ets_proofOfOrigin = 251;      
      NID_id_smime_cti_ets_proofOfReceipt = 252;      
      NID_id_smime_cti_ets_proofOfDelivery = 253;      
      NID_id_smime_cti_ets_proofOfSender = 254;      
      NID_id_smime_cti_ets_proofOfApproval = 255;      
      NID_id_smime_cti_ets_proofOfCreation = 256;      
      NID_friendlyName = 156;      
      NID_localKeyID = 157;      
      NID_ms_csp_name = 417;      
      NID_LocalKeySet = 856;      
      NID_x509Certificate = 158;      
      NID_sdsiCertificate = 159;      
      NID_x509Crl = 160;      
      NID_pbe_WithSHA1And128BitRC4 = 144;      
      NID_pbe_WithSHA1And40BitRC4 = 145;      
      NID_pbe_WithSHA1And3_Key_TripleDES_CBC = 146;      
      NID_pbe_WithSHA1And2_Key_TripleDES_CBC = 147;      
      NID_pbe_WithSHA1And128BitRC2_CBC = 148;      
      NID_pbe_WithSHA1And40BitRC2_CBC = 149;      
      NID_keyBag = 150;      
      NID_pkcs8ShroudedKeyBag = 151;      
      NID_certBag = 152;      
      NID_crlBag = 153;      
      NID_secretBag = 154;      
      NID_safeContentsBag = 155;      
      NID_md2 = 3;      
      NID_md4 = 257;      
      NID_md5 = 4;      
      NID_md5_sha1 = 114;      
      NID_hmacWithMD5 = 797;      
      NID_hmacWithSHA1 = 163;      
      NID_hmacWithSHA224 = 798;      
      NID_hmacWithSHA256 = 799;      
      NID_hmacWithSHA384 = 800;      
      NID_hmacWithSHA512 = 801;      
      NID_rc2_cbc = 37;      
      NID_rc2_ecb = 38;      
      NID_rc2_cfb64 = 39;      
      NID_rc2_ofb64 = 40;      
      NID_rc2_40_cbc = 98;      
      NID_rc2_64_cbc = 166;      
      NID_rc4 = 5;      
      NID_rc4_40 = 97;      
      NID_des_ede3_cbc = 44;      
      NID_rc5_cbc = 120;      
      NID_rc5_ecb = 121;      
      NID_rc5_cfb64 = 122;      
      NID_rc5_ofb64 = 123;      
      NID_ms_ext_req = 171;      
      NID_ms_code_ind = 134;      
      NID_ms_code_com = 135;      
      NID_ms_ctl_sign = 136;      
      NID_ms_sgc = 137;      
      NID_ms_efs = 138;      
      NID_ms_smartcard_login = 648;      
      NID_ms_upn = 649;      
      NID_idea_cbc = 34;      
      NID_idea_ecb = 36;      
      NID_idea_cfb64 = 35;      
      NID_idea_ofb64 = 46;      
      NID_bf_cbc = 91;      
      NID_bf_ecb = 92;      
      NID_bf_cfb64 = 93;      
      NID_bf_ofb64 = 94;      
      NID_id_pkix = 127;      
      NID_id_pkix_mod = 258;      
      NID_id_pe = 175;      
      NID_id_qt = 259;      
      NID_id_kp = 128;      
      NID_id_it = 260;      
      NID_id_pkip = 261;      
      NID_id_alg = 262;      
      NID_id_cmc = 263;      
      NID_id_on = 264;      
      NID_id_pda = 265;      
      NID_id_aca = 266;      
      NID_id_qcs = 267;      
      NID_id_cct = 268;      
      NID_id_ppl = 662;      
      NID_id_ad = 176;      
      NID_id_pkix1_explicit_88 = 269;      
      NID_id_pkix1_implicit_88 = 270;      
      NID_id_pkix1_explicit_93 = 271;      
      NID_id_pkix1_implicit_93 = 272;      
      NID_id_mod_crmf = 273;      
      NID_id_mod_cmc = 274;      
      NID_id_mod_kea_profile_88 = 275;      
      NID_id_mod_kea_profile_93 = 276;      
      NID_id_mod_cmp = 277;      
      NID_id_mod_qualified_cert_88 = 278;      
      NID_id_mod_qualified_cert_93 = 279;      
      NID_id_mod_attribute_cert = 280;      
      NID_id_mod_timestamp_protocol = 281;      
      NID_id_mod_ocsp = 282;      
      NID_id_mod_dvcs = 283;      
      NID_id_mod_cmp2000 = 284;      
      NID_info_access = 177;      
      NID_biometricInfo = 285;      
      NID_qcStatements = 286;      
      NID_ac_auditEntity = 287;      
      NID_ac_targeting = 288;      
      NID_aaControls = 289;      
      NID_sbgp_ipAddrBlock = 290;      
      NID_sbgp_autonomousSysNum = 291;      
      NID_sbgp_routerIdentifier = 292;      
      NID_ac_proxying = 397;      
      NID_sinfo_access = 398;      
      NID_proxyCertInfo = 663;      
      NID_tlsfeature = 1020;      
      NID_id_qt_cps = 164;      
      NID_id_qt_unotice = 165;      
      NID_textNotice = 293;      
      NID_server_auth = 129;      
      NID_client_auth = 130;      
      NID_code_sign = 131;      
      NID_email_protect = 132;      
      NID_ipsecEndSystem = 294;      
      NID_ipsecTunnel = 295;      
      NID_ipsecUser = 296;      
      NID_time_stamp = 133;      
      NID_OCSP_sign = 180;      
      NID_dvcs = 297;      
      NID_ipsec_IKE = 1022;      
      NID_capwapAC = 1023;      
      NID_capwapWTP = 1024;      
      NID_sshClient = 1025;      
      NID_sshServer = 1026;      
      NID_sendRouter = 1027;      
      NID_sendProxiedRouter = 1028;      
      NID_sendOwner = 1029;      
      NID_sendProxiedOwner = 1030;      
      NID_id_it_caProtEncCert = 298;      
      NID_id_it_signKeyPairTypes = 299;      
      NID_id_it_encKeyPairTypes = 300;      
      NID_id_it_preferredSymmAlg = 301;      
      NID_id_it_caKeyUpdateInfo = 302;      
      NID_id_it_currentCRL = 303;      
      NID_id_it_unsupportedOIDs = 304;      
      NID_id_it_subscriptionRequest = 305;      
      NID_id_it_subscriptionResponse = 306;      
      NID_id_it_keyPairParamReq = 307;      
      NID_id_it_keyPairParamRep = 308;      
      NID_id_it_revPassphrase = 309;      
      NID_id_it_implicitConfirm = 310;      
      NID_id_it_confirmWaitTime = 311;      
      NID_id_it_origPKIMessage = 312;      
      NID_id_it_suppLangTags = 784;      
      NID_id_regCtrl = 313;      
      NID_id_regInfo = 314;      
      NID_id_regCtrl_regToken = 315;      
      NID_id_regCtrl_authenticator = 316;      
      NID_id_regCtrl_pkiPublicationInfo = 317;      
      NID_id_regCtrl_pkiArchiveOptions = 318;      
      NID_id_regCtrl_oldCertID = 319;      
      NID_id_regCtrl_protocolEncrKey = 320;      
      NID_id_regInfo_utf8Pairs = 321;      
      NID_id_regInfo_certReq = 322;      
      NID_id_alg_des40 = 323;      
      NID_id_alg_noSignature = 324;      
      NID_id_alg_dh_sig_hmac_sha1 = 325;      
      NID_id_alg_dh_pop = 326;      
      NID_id_cmc_statusInfo = 327;      
      NID_id_cmc_identification = 328;      
      NID_id_cmc_identityProof = 329;      
      NID_id_cmc_dataReturn = 330;      
      NID_id_cmc_transactionId = 331;      
      NID_id_cmc_senderNonce = 332;      
      NID_id_cmc_recipientNonce = 333;      
      NID_id_cmc_addExtensions = 334;      
      NID_id_cmc_encryptedPOP = 335;      
      NID_id_cmc_decryptedPOP = 336;      
      NID_id_cmc_lraPOPWitness = 337;      
      NID_id_cmc_getCert = 338;      
      NID_id_cmc_getCRL = 339;      
      NID_id_cmc_revokeRequest = 340;      
      NID_id_cmc_regInfo = 341;      
      NID_id_cmc_responseInfo = 342;      
      NID_id_cmc_queryPending = 343;      
      NID_id_cmc_popLinkRandom = 344;      
      NID_id_cmc_popLinkWitness = 345;      
      NID_id_cmc_confirmCertAcceptance = 346;      
      NID_id_on_personalData = 347;      
      NID_id_on_permanentIdentifier = 858;      
      NID_id_pda_dateOfBirth = 348;      
      NID_id_pda_placeOfBirth = 349;      
      NID_id_pda_gender = 351;      
      NID_id_pda_countryOfCitizenship = 352;      
      NID_id_pda_countryOfResidence = 353;      
      NID_id_aca_authenticationInfo = 354;      
      NID_id_aca_accessIdentity = 355;      
      NID_id_aca_chargingIdentity = 356;      
      NID_id_aca_group = 357;      
      NID_id_aca_role = 358;      
      NID_id_aca_encAttrs = 399;      
      NID_id_qcs_pkixQCSyntax_v1 = 359;      
      NID_id_cct_crs = 360;      
      NID_id_cct_PKIData = 361;      
      NID_id_cct_PKIResponse = 362;      
      NID_id_ppl_anyLanguage = 664;      
      NID_id_ppl_inheritAll = 665;      
      NID_Independent = 667;      
      NID_ad_OCSP = 178;      
      NID_ad_ca_issuers = 179;      
      NID_ad_timeStamping = 363;      
      NID_ad_dvcs = 364;      
      NID_caRepository = 785;      
      NID_id_pkix_OCSP_basic = 365;      
      NID_id_pkix_OCSP_Nonce = 366;      
      NID_id_pkix_OCSP_CrlID = 367;      
      NID_id_pkix_OCSP_acceptableResponses = 368;      
      NID_id_pkix_OCSP_noCheck = 369;      
      NID_id_pkix_OCSP_archiveCutoff = 370;      
      NID_id_pkix_OCSP_serviceLocator = 371;      
      NID_id_pkix_OCSP_extendedStatus = 372;      
      NID_id_pkix_OCSP_valid = 373;      
      NID_id_pkix_OCSP_path = 374;      
      NID_id_pkix_OCSP_trustRoot = 375;      
      NID_algorithm = 376;      
      NID_md5WithRSA = 104;      
      NID_des_ecb = 29;      
      NID_des_cbc = 31;      
      NID_des_ofb64 = 45;      
      NID_des_cfb64 = 30;      
      NID_rsaSignature = 377;      
      NID_dsa_2 = 67;      
      NID_dsaWithSHA = 66;      
      NID_shaWithRSAEncryption = 42;      
      NID_des_ede_ecb = 32;      
      NID_des_ede3_ecb = 33;      
      NID_des_ede_cbc = 43;      
      NID_des_ede_cfb64 = 60;      
      NID_des_ede3_cfb64 = 61;      
      NID_des_ede_ofb64 = 62;      
      NID_des_ede3_ofb64 = 63;      
      NID_desx_cbc = 80;      
      NID_sha = 41;      
      NID_sha1 = 64;      
      NID_dsaWithSHA1_2 = 70;      
      NID_sha1WithRSA = 115;      
      NID_ripemd160 = 117;      
      NID_ripemd160WithRSA = 119;      
      NID_blake2b512 = 1056;      
      NID_blake2s256 = 1057;      
      NID_sxnet = 143;      
      NID_X500 = 11;      
      NID_X509 = 12;      
      NID_commonName = 13;      
      NID_surname = 100;      
      NID_serialNumber = 105;      
      NID_countryName = 14;      
      NID_localityName = 15;      
      NID_stateOrProvinceName = 16;      
      NID_streetAddress = 660;      
      NID_organizationName = 17;      
      NID_organizationalUnitName = 18;      
      NID_title = 106;      
      NID_description = 107;      
      NID_searchGuide = 859;      
      NID_businessCategory = 860;      
      NID_postalAddress = 861;      
      NID_postalCode = 661;      
      NID_postOfficeBox = 862;      
      NID_physicalDeliveryOfficeName = 863;      
      NID_telephoneNumber = 864;      
      NID_telexNumber = 865;      
      NID_teletexTerminalIdentifier = 866;      
      NID_facsimileTelephoneNumber = 867;      
      NID_x121Address = 868;      
      NID_internationaliSDNNumber = 869;      
      NID_registeredAddress = 870;      
      NID_destinationIndicator = 871;      
      NID_preferredDeliveryMethod = 872;      
      NID_presentationAddress = 873;      
      NID_supportedApplicationContext = 874;      
      NID_member = 875;      
      NID_owner = 876;      
      NID_roleOccupant = 877;      
      NID_seeAlso = 878;      
      NID_userPassword = 879;      
      NID_userCertificate = 880;      
      NID_cACertificate = 881;      
      NID_authorityRevocationList = 882;      
      NID_certificateRevocationList = 883;      
      NID_crossCertificatePair = 884;      
      NID_name = 173;      
      NID_givenName = 99;      
      NID_initials = 101;      
      NID_generationQualifier = 509;      
      NID_x500UniqueIdentifier = 503;      
      NID_dnQualifier = 174;      
      NID_enhancedSearchGuide = 885;      
      NID_protocolInformation = 886;      
      NID_distinguishedName = 887;      
      NID_uniqueMember = 888;      
      NID_houseIdentifier = 889;      
      NID_supportedAlgorithms = 890;      
      NID_deltaRevocationList = 891;      
      NID_dmdName = 892;      
      NID_pseudonym = 510;      
      NID_role = 400;      
      NID_X500algorithms = 378;      
      NID_rsa = 19;      
      NID_mdc2WithRSA = 96;      
      NID_mdc2 = 95;      
      NID_id_ce = 81;      
      NID_subject_directory_attributes = 769;      
      NID_subject_key_identifier = 82;      
      NID_key_usage = 83;      
      NID_private_key_usage_period = 84;      
      NID_subject_alt_name = 85;      
      NID_issuer_alt_name = 86;      
      NID_basic_constraints = 87;      
      NID_crl_number = 88;      
      NID_crl_reason = 141;      
      NID_invalidity_date = 142;      
      NID_delta_crl = 140;      
      NID_issuing_distribution_point = 770;      
      NID_certificate_issuer = 771;      
      NID_name_constraints = 666;      
      NID_crl_distribution_points = 103;      
      NID_certificate_policies = 89;      
      NID_any_policy = 746;      
      NID_policy_mappings = 747;      
      NID_authority_key_identifier = 90;      
      NID_policy_constraints = 401;      
      NID_ext_key_usage = 126;      
      NID_freshest_crl = 857;      
      NID_inhibit_any_policy = 748;      
      NID_target_information = 402;      
      NID_no_rev_avail = 403;      
      NID_anyExtendedKeyUsage = 910;      
      NID_netscape = 57;      
      NID_netscape_cert_extension = 58;      
      NID_netscape_data_type = 59;      
      NID_netscape_cert_type = 71;      
      NID_netscape_base_url = 72;      
      NID_netscape_revocation_url = 73;      
      NID_netscape_ca_revocation_url = 74;      
      NID_netscape_renewal_url = 75;      
      NID_netscape_ca_policy_url = 76;      
      NID_netscape_ssl_server_name = 77;      
      NID_netscape_comment = 78;      
      NID_netscape_cert_sequence = 79;      
      NID_ns_sgc = 139;      
      NID_org = 379;      
      NID_dod = 380;      
      NID_iana = 381;      
      NID_Directory = 382;      
      NID_Management = 383;      
      NID_Experimental = 384;      
      NID_Private = 385;      
      NID_Security = 386;      
      NID_SNMPv2 = 387;      
      NID_Mail = 388;      
      NID_Enterprises = 389;      
      NID_dcObject = 390;      
      NID_mime_mhs = 504;      
      NID_mime_mhs_headings = 505;      
      NID_mime_mhs_bodies = 506;      
      NID_id_hex_partial_message = 507;      
      NID_id_hex_multipart_message = 508;      
      NID_zlib_compression = 125;      
      NID_aes_128_ecb = 418;      
      NID_aes_128_cbc = 419;      
      NID_aes_128_ofb128 = 420;      
      NID_aes_128_cfb128 = 421;      
      NID_id_aes128_wrap = 788;      
      NID_aes_128_gcm = 895;      
      NID_aes_128_ccm = 896;      
      NID_id_aes128_wrap_pad = 897;      
      NID_aes_192_ecb = 422;      
      NID_aes_192_cbc = 423;      
      NID_aes_192_ofb128 = 424;      
      NID_aes_192_cfb128 = 425;      
      NID_id_aes192_wrap = 789;      
      NID_aes_192_gcm = 898;      
      NID_aes_192_ccm = 899;      
      NID_id_aes192_wrap_pad = 900;      
      NID_aes_256_ecb = 426;      
      NID_aes_256_cbc = 427;      
      NID_aes_256_ofb128 = 428;      
      NID_aes_256_cfb128 = 429;      
      NID_id_aes256_wrap = 790;      
      NID_aes_256_gcm = 901;      
      NID_aes_256_ccm = 902;      
      NID_id_aes256_wrap_pad = 903;      
      NID_aes_128_cfb1 = 650;      
      NID_aes_192_cfb1 = 651;      
      NID_aes_256_cfb1 = 652;      
      NID_aes_128_cfb8 = 653;      
      NID_aes_192_cfb8 = 654;      
      NID_aes_256_cfb8 = 655;      
      NID_aes_128_ctr = 904;      
      NID_aes_192_ctr = 905;      
      NID_aes_256_ctr = 906;      
      NID_aes_128_ocb = 958;      
      NID_aes_192_ocb = 959;      
      NID_aes_256_ocb = 960;      
      NID_aes_128_xts = 913;      
      NID_aes_256_xts = 914;      
      NID_des_cfb1 = 656;      
      NID_des_cfb8 = 657;      
      NID_des_ede3_cfb1 = 658;      
      NID_des_ede3_cfb8 = 659;      
      NID_sha256 = 672;      
      NID_sha384 = 673;      
      NID_sha512 = 674;      
      NID_sha224 = 675;      
      NID_dsa_with_SHA224 = 802;      
      NID_dsa_with_SHA256 = 803;      
      NID_hold_instruction_code = 430;      
      NID_hold_instruction_none = 431;      
      NID_hold_instruction_call_issuer = 432;      
      NID_hold_instruction_reject = 433;      
      NID_data = 434;      
      NID_pss = 435;      
      NID_ucl = 436;      
      NID_pilot = 437;      
      NID_pilotAttributeType = 438;      
      NID_pilotAttributeSyntax = 439;      
      NID_pilotObjectClass = 440;      
      NID_pilotGroups = 441;      
      NID_iA5StringSyntax = 442;      
      NID_caseIgnoreIA5StringSyntax = 443;      
      NID_pilotObject = 444;      
      NID_pilotPerson = 445;      
      NID_account = 446;      
      NID_document = 447;      
      NID_room = 448;      
      NID_documentSeries = 449;      
      NID_Domain = 392;      
      NID_rFC822localPart = 450;      
      NID_dNSDomain = 451;      
      NID_domainRelatedObject = 452;      
      NID_friendlyCountry = 453;      
      NID_simpleSecurityObject = 454;      
      NID_pilotOrganization = 455;      
      NID_pilotDSA = 456;      
      NID_qualityLabelledData = 457;      
      NID_userId = 458;      
      NID_textEncodedORAddress = 459;      
      NID_rfc822Mailbox = 460;      
      NID_info = 461;      
      NID_favouriteDrink = 462;      
      NID_roomNumber = 463;      
      NID_photo = 464;      
      NID_userClass = 465;      
      NID_host = 466;      
      NID_manager = 467;      
      NID_documentIdentifier = 468;      
      NID_documentTitle = 469;      
      NID_documentVersion = 470;      
      NID_documentAuthor = 471;      
      NID_documentLocation = 472;      
      NID_homeTelephoneNumber = 473;      
      NID_secretary = 474;      
      NID_otherMailbox = 475;      
      NID_lastModifiedTime = 476;      
      NID_lastModifiedBy = 477;      
      NID_domainComponent = 391;      
      NID_aRecord = 478;      
      NID_pilotAttributeType27 = 479;      
      NID_mXRecord = 480;      
      NID_nSRecord = 481;      
      NID_sOARecord = 482;      
      NID_cNAMERecord = 483;      
      NID_associatedDomain = 484;      
      NID_associatedName = 485;      
      NID_homePostalAddress = 486;      
      NID_personalTitle = 487;      
      NID_mobileTelephoneNumber = 488;      
      NID_pagerTelephoneNumber = 489;      
      NID_friendlyCountryName = 490;      
      NID_uniqueIdentifier = 102;      
      NID_organizationalStatus = 491;      
      NID_janetMailbox = 492;      
      NID_mailPreferenceOption = 493;      
      NID_buildingName = 494;      
      NID_dSAQuality = 495;      
      NID_singleLevelQuality = 496;      
      NID_subtreeMinimumQuality = 497;      
      NID_subtreeMaximumQuality = 498;      
      NID_personalSignature = 499;      
      NID_dITRedirect = 500;      
      NID_audio = 501;      
      NID_documentPublisher = 502;      
      NID_id_set = 512;      
      NID_set_ctype = 513;      
      NID_set_msgExt = 514;      
      NID_set_attr = 515;      
      NID_set_policy = 516;      
      NID_set_certExt = 517;      
      NID_set_brand = 518;      
      NID_setct_PANData = 519;      
      NID_setct_PANToken = 520;      
      NID_setct_PANOnly = 521;      
      NID_setct_OIData = 522;      
      NID_setct_PI = 523;      
      NID_setct_PIData = 524;      
      NID_setct_PIDataUnsigned = 525;      
      NID_setct_HODInput = 526;      
      NID_setct_AuthResBaggage = 527;      
      NID_setct_AuthRevReqBaggage = 528;      
      NID_setct_AuthRevResBaggage = 529;      
      NID_setct_CapTokenSeq = 530;      
      NID_setct_PInitResData = 531;      
      NID_setct_PI_TBS = 532;      
      NID_setct_PResData = 533;      
      NID_setct_AuthReqTBS = 534;      
      NID_setct_AuthResTBS = 535;      
      NID_setct_AuthResTBSX = 536;      
      NID_setct_AuthTokenTBS = 537;      
      NID_setct_CapTokenData = 538;      
      NID_setct_CapTokenTBS = 539;      
      NID_setct_AcqCardCodeMsg = 540;      
      NID_setct_AuthRevReqTBS = 541;      
      NID_setct_AuthRevResData = 542;      
      NID_setct_AuthRevResTBS = 543;      
      NID_setct_CapReqTBS = 544;      
      NID_setct_CapReqTBSX = 545;      
      NID_setct_CapResData = 546;      
      NID_setct_CapRevReqTBS = 547;      
      NID_setct_CapRevReqTBSX = 548;      
      NID_setct_CapRevResData = 549;      
      NID_setct_CredReqTBS = 550;      
      NID_setct_CredReqTBSX = 551;      
      NID_setct_CredResData = 552;      
      NID_setct_CredRevReqTBS = 553;      
      NID_setct_CredRevReqTBSX = 554;      
      NID_setct_CredRevResData = 555;      
      NID_setct_PCertReqData = 556;      
      NID_setct_PCertResTBS = 557;      
      NID_setct_BatchAdminReqData = 558;      
      NID_setct_BatchAdminResData = 559;      
      NID_setct_CardCInitResTBS = 560;      
      NID_setct_MeAqCInitResTBS = 561;      
      NID_setct_RegFormResTBS = 562;      
      NID_setct_CertReqData = 563;      
      NID_setct_CertReqTBS = 564;      
      NID_setct_CertResData = 565;      
      NID_setct_CertInqReqTBS = 566;      
      NID_setct_ErrorTBS = 567;      
      NID_setct_PIDualSignedTBE = 568;      
      NID_setct_PIUnsignedTBE = 569;      
      NID_setct_AuthReqTBE = 570;      
      NID_setct_AuthResTBE = 571;      
      NID_setct_AuthResTBEX = 572;      
      NID_setct_AuthTokenTBE = 573;      
      NID_setct_CapTokenTBE = 574;      
      NID_setct_CapTokenTBEX = 575;      
      NID_setct_AcqCardCodeMsgTBE = 576;      
      NID_setct_AuthRevReqTBE = 577;      
      NID_setct_AuthRevResTBE = 578;      
      NID_setct_AuthRevResTBEB = 579;      
      NID_setct_CapReqTBE = 580;      
      NID_setct_CapReqTBEX = 581;      
      NID_setct_CapResTBE = 582;      
      NID_setct_CapRevReqTBE = 583;      
      NID_setct_CapRevReqTBEX = 584;      
      NID_setct_CapRevResTBE = 585;      
      NID_setct_CredReqTBE = 586;      
      NID_setct_CredReqTBEX = 587;      
      NID_setct_CredResTBE = 588;      
      NID_setct_CredRevReqTBE = 589;      
      NID_setct_CredRevReqTBEX = 590;      
      NID_setct_CredRevResTBE = 591;      
      NID_setct_BatchAdminReqTBE = 592;      
      NID_setct_BatchAdminResTBE = 593;      
      NID_setct_RegFormReqTBE = 594;      
      NID_setct_CertReqTBE = 595;      
      NID_setct_CertReqTBEX = 596;      
      NID_setct_CertResTBE = 597;      
      NID_setct_CRLNotificationTBS = 598;      
      NID_setct_CRLNotificationResTBS = 599;      
      NID_setct_BCIDistributionTBS = 600;      
      NID_setext_genCrypt = 601;      
      NID_setext_miAuth = 602;      
      NID_setext_pinSecure = 603;      
      NID_setext_pinAny = 604;      
      NID_setext_track2 = 605;      
      NID_setext_cv = 606;      
      NID_set_policy_root = 607;      
      NID_setCext_hashedRoot = 608;      
      NID_setCext_certType = 609;      
      NID_setCext_merchData = 610;      
      NID_setCext_cCertRequired = 611;      
      NID_setCext_tunneling = 612;      
      NID_setCext_setExt = 613;      
      NID_setCext_setQualf = 614;      
      NID_setCext_PGWYcapabilities = 615;      
      NID_setCext_TokenIdentifier = 616;      
      NID_setCext_Track2Data = 617;      
      NID_setCext_TokenType = 618;      
      NID_setCext_IssuerCapabilities = 619;      
      NID_setAttr_Cert = 620;      
      NID_setAttr_PGWYcap = 621;      
      NID_setAttr_TokenType = 622;      
      NID_setAttr_IssCap = 623;      
      NID_set_rootKeyThumb = 624;      
      NID_set_addPolicy = 625;      
      NID_setAttr_Token_EMV = 626;      
      NID_setAttr_Token_B0Prime = 627;      
      NID_setAttr_IssCap_CVM = 628;      
      NID_setAttr_IssCap_T2 = 629;      
      NID_setAttr_IssCap_Sig = 630;      
      NID_setAttr_GenCryptgrm = 631;      
      NID_setAttr_T2Enc = 632;      
      NID_setAttr_T2cleartxt = 633;      
      NID_setAttr_TokICCsig = 634;      
      NID_setAttr_SecDevSig = 635;      
      NID_set_brand_IATA_ATA = 636;      
      NID_set_brand_Diners = 637;      
      NID_set_brand_AmericanExpress = 638;      
      NID_set_brand_JCB = 639;      
      NID_set_brand_Visa = 640;      
      NID_set_brand_MasterCard = 641;      
      NID_set_brand_Novus = 642;      
      NID_des_cdmf = 643;      
      NID_rsaOAEPEncryptionSET = 644;      
      NID_ipsec3 = 749;      
      NID_ipsec4 = 750;      
      NID_whirlpool = 804;      
      NID_cryptopro = 805;      
      NID_cryptocom = 806;      
      NID_id_tc26 = 974;      
      NID_id_GostR3411_94_with_GostR3410_2001 = 807;      
      NID_id_GostR3411_94_with_GostR3410_94 = 808;      
      NID_id_GostR3411_94 = 809;      
      NID_id_HMACGostR3411_94 = 810;      
      NID_id_GostR3410_2001 = 811;      
      NID_id_GostR3410_94 = 812;      
      NID_id_Gost28147_89 = 813;      
      NID_gost89_cnt = 814;      
      NID_gost89_cnt_12 = 975;      
      NID_gost89_cbc = 1009;      
      NID_gost89_ecb = 1010;      
      NID_gost89_ctr = 1011;      
      NID_id_Gost28147_89_MAC = 815;      
      NID_gost_mac_12 = 976;      
      NID_id_GostR3411_94_prf = 816;      
      NID_id_GostR3410_2001DH = 817;      
      NID_id_GostR3410_94DH = 818;      
      NID_id_Gost28147_89_CryptoPro_KeyMeshing = 819;      
      NID_id_Gost28147_89_None_KeyMeshing = 820;      
      NID_id_GostR3411_94_TestParamSet = 821;      
      NID_id_GostR3411_94_CryptoProParamSet = 822;      
      NID_id_Gost28147_89_TestParamSet = 823;      
      NID_id_Gost28147_89_CryptoPro_A_ParamSet = 824;      
      NID_id_Gost28147_89_CryptoPro_B_ParamSet = 825;      
      NID_id_Gost28147_89_CryptoPro_C_ParamSet = 826;      
      NID_id_Gost28147_89_CryptoPro_D_ParamSet = 827;      
      NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = 828;      
      NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = 829;      
      NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet = 830;      
      NID_id_GostR3410_94_TestParamSet = 831;      
      NID_id_GostR3410_94_CryptoPro_A_ParamSet = 832;      
      NID_id_GostR3410_94_CryptoPro_B_ParamSet = 833;      
      NID_id_GostR3410_94_CryptoPro_C_ParamSet = 834;      
      NID_id_GostR3410_94_CryptoPro_D_ParamSet = 835;      
      NID_id_GostR3410_94_CryptoPro_XchA_ParamSet = 836;      
      NID_id_GostR3410_94_CryptoPro_XchB_ParamSet = 837;      
      NID_id_GostR3410_94_CryptoPro_XchC_ParamSet = 838;      
      NID_id_GostR3410_2001_TestParamSet = 839;      
      NID_id_GostR3410_2001_CryptoPro_A_ParamSet = 840;      
      NID_id_GostR3410_2001_CryptoPro_B_ParamSet = 841;      
      NID_id_GostR3410_2001_CryptoPro_C_ParamSet = 842;      
      NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet = 843;      
      NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet = 844;      
      NID_id_GostR3410_94_a = 845;      
      NID_id_GostR3410_94_aBis = 846;      
      NID_id_GostR3410_94_b = 847;      
      NID_id_GostR3410_94_bBis = 848;      
      NID_id_Gost28147_89_cc = 849;      
      NID_id_GostR3410_94_cc = 850;      
      NID_id_GostR3410_2001_cc = 851;      
      NID_id_GostR3411_94_with_GostR3410_94_cc = 852;      
      NID_id_GostR3411_94_with_GostR3410_2001_cc = 853;      
      NID_id_GostR3410_2001_ParamSet_cc = 854;      
      NID_id_tc26_algorithms = 977;      
      NID_id_tc26_sign = 978;      
      NID_id_GostR3410_2012_256 = 979;      
      NID_id_GostR3410_2012_512 = 980;      
      NID_id_tc26_digest = 981;      
      NID_id_GostR3411_2012_256 = 982;      
      NID_id_GostR3411_2012_512 = 983;      
      NID_id_tc26_signwithdigest = 984;      
      NID_id_tc26_signwithdigest_gost3410_2012_256 = 985;      
      NID_id_tc26_signwithdigest_gost3410_2012_512 = 986;      
      NID_id_tc26_mac = 987;      
      NID_id_tc26_hmac_gost_3411_2012_256 = 988;      
      NID_id_tc26_hmac_gost_3411_2012_512 = 989;      
      NID_id_tc26_cipher = 990;      
      NID_id_tc26_agreement = 991;      
      NID_id_tc26_agreement_gost_3410_2012_256 = 992;      
      NID_id_tc26_agreement_gost_3410_2012_512 = 993;      
      NID_id_tc26_constants = 994;      
      NID_id_tc26_sign_constants = 995;      
      NID_id_tc26_gost_3410_2012_512_constants = 996;      
      NID_id_tc26_gost_3410_2012_512_paramSetTest = 997;      
      NID_id_tc26_gost_3410_2012_512_paramSetA = 998;      
      NID_id_tc26_gost_3410_2012_512_paramSetB = 999;      
      NID_id_tc26_digest_constants = 1000;      
      NID_id_tc26_cipher_constants = 1001;      
      NID_id_tc26_gost_28147_constants = 1002;      
      NID_id_tc26_gost_28147_param_Z = 1003;      
      NID_INN = 1004;      
      NID_OGRN = 1005;      
      NID_SNILS = 1006;      
      NID_subjectSignTool = 1007;      
      NID_issuerSignTool = 1008;      
      NID_grasshopper_ecb = 1012;      
      NID_grasshopper_ctr = 1013;      
      NID_grasshopper_ofb = 1014;      
      NID_grasshopper_cbc = 1015;      
      NID_grasshopper_cfb = 1016;      
      NID_grasshopper_mac = 1017;      
      NID_camellia_128_cbc = 751;      
      NID_camellia_192_cbc = 752;      
      NID_camellia_256_cbc = 753;      
      NID_id_camellia128_wrap = 907;      
      NID_id_camellia192_wrap = 908;      
      NID_id_camellia256_wrap = 909;      
      NID_camellia_128_ecb = 754;      
      NID_camellia_128_ofb128 = 766;      
      NID_camellia_128_cfb128 = 757;      
      NID_camellia_128_gcm = 961;      
      NID_camellia_128_ccm = 962;      
      NID_camellia_128_ctr = 963;      
      NID_camellia_128_cmac = 964;      
      NID_camellia_192_ecb = 755;      
      NID_camellia_192_ofb128 = 767;      
      NID_camellia_192_cfb128 = 758;      
      NID_camellia_192_gcm = 965;      
      NID_camellia_192_ccm = 966;      
      NID_camellia_192_ctr = 967;      
      NID_camellia_192_cmac = 968;      
      NID_camellia_256_ecb = 756;      
      NID_camellia_256_ofb128 = 768;      
      NID_camellia_256_cfb128 = 759;      
      NID_camellia_256_gcm = 969;      
      NID_camellia_256_ccm = 970;      
      NID_camellia_256_ctr = 971;      
      NID_camellia_256_cmac = 972;      
      NID_camellia_128_cfb1 = 760;      
      NID_camellia_192_cfb1 = 761;      
      NID_camellia_256_cfb1 = 762;      
      NID_camellia_128_cfb8 = 763;      
      NID_camellia_192_cfb8 = 764;      
      NID_camellia_256_cfb8 = 765;      
      NID_kisa = 773;      
      NID_seed_ecb = 776;      
      NID_seed_cbc = 777;      
      NID_seed_cfb128 = 779;      
      NID_seed_ofb128 = 778;      
      NID_hmac = 855;      
      NID_cmac = 894;      
      NID_rc4_hmac_md5 = 915;      
      NID_aes_128_cbc_hmac_sha1 = 916;      
      NID_aes_192_cbc_hmac_sha1 = 917;      
      NID_aes_256_cbc_hmac_sha1 = 918;      
      NID_aes_128_cbc_hmac_sha256 = 948;      
      NID_aes_192_cbc_hmac_sha256 = 949;      
      NID_aes_256_cbc_hmac_sha256 = 950;      
      NID_chacha20_poly1305 = 1018;      
      NID_chacha20 = 1019;      
      NID_dhpublicnumber = 920;      
      NID_brainpoolP160r1 = 921;      
      NID_brainpoolP160t1 = 922;      
      NID_brainpoolP192r1 = 923;      
      NID_brainpoolP192t1 = 924;      
      NID_brainpoolP224r1 = 925;      
      NID_brainpoolP224t1 = 926;      
      NID_brainpoolP256r1 = 927;      
      NID_brainpoolP256t1 = 928;      
      NID_brainpoolP320r1 = 929;      
      NID_brainpoolP320t1 = 930;      
      NID_brainpoolP384r1 = 931;      
      NID_brainpoolP384t1 = 932;      
      NID_brainpoolP512r1 = 933;      
      NID_brainpoolP512t1 = 934;      
      NID_dhSinglePass_stdDH_sha1kdf_scheme = 936;      
      NID_dhSinglePass_stdDH_sha224kdf_scheme = 937;      
      NID_dhSinglePass_stdDH_sha256kdf_scheme = 938;      
      NID_dhSinglePass_stdDH_sha384kdf_scheme = 939;      
      NID_dhSinglePass_stdDH_sha512kdf_scheme = 940;      
      NID_dhSinglePass_cofactorDH_sha1kdf_scheme = 941;      
      NID_dhSinglePass_cofactorDH_sha224kdf_scheme = 942;      
      NID_dhSinglePass_cofactorDH_sha256kdf_scheme = 943;      
      NID_dhSinglePass_cofactorDH_sha384kdf_scheme = 944;      
      NID_dhSinglePass_cofactorDH_sha512kdf_scheme = 945;      
      NID_dh_std_kdf = 946;      
      NID_dh_cofactor_kdf = 947;      
      NID_ct_precert_scts = 951;      
      NID_ct_precert_poison = 952;      
      NID_ct_precert_signer = 953;      
      NID_ct_cert_scts = 954;      
      NID_jurisdictionLocalityName = 955;      
      NID_jurisdictionStateOrProvinceName = 956;      
      NID_jurisdictionCountryName = 957;      
      NID_id_scrypt = 973;      
      NID_tls1_prf = 1021;      
      NID_hkdf = 1036;      
      NID_id_pkinit = 1031;      
      NID_pkInitClientAuth = 1032;      
      NID_pkInitKDC = 1033;      
      NID_X25519 = 1034;      
      NID_X448 = 1035;      
      NID_kx_rsa = 1037;      
      NID_kx_ecdhe = 1038;      
      NID_kx_dhe = 1039;      
      NID_kx_ecdhe_psk = 1040;      
      NID_kx_dhe_psk = 1041;      
      NID_kx_rsa_psk = 1042;      
      NID_kx_psk = 1043;      
      NID_kx_srp = 1044;      
      NID_kx_gost = 1045;      
      NID_auth_rsa = 1046;      
      NID_auth_ecdsa = 1047;      
      NID_auth_psk = 1048;      
      NID_auth_dss = 1049;      
      NID_auth_gost01 = 1050;      
      NID_auth_gost12 = 1051;      
      NID_auth_srp = 1052;      
      NID_auth_null = 1053;      
{$define HEADER_ASN1_H}    
{$define HEADER_BN_H}    

    const
      BN_FLG_MALLOCED = $01;      
      BN_FLG_STATIC_DATA = $02;      
      BN_FLG_CONSTTIME = $04;      
      BN_FLG_SECURE = $08;      
      BN_FLG_EXP_CONSTTIME = BN_FLG_CONSTTIME;      
      BN_FLG_FREE = $8000;      

procedure BN_set_flags(b:PBIGNUM; n:cint);cdecl; external DLLUtilName;
function  BN_get_flags(b:PBIGNUM; n:cint):cint;cdecl; external DLLUtilName;

    const
      BN_RAND_TOP_ANY = -(1);      
      BN_RAND_TOP_ONE = 0;      
      BN_RAND_TOP_TWO = 1;      
      BN_RAND_BOTTOM_ANY = 0;      
      BN_RAND_BOTTOM_ODD = 1;      

type
  TCB_BN_GENCB_set=function(para1:cint; para2:cint; para3:PBN_GENCB):cint; cdecl;

procedure BN_with_flags(dest:PBIGNUM; b:PBIGNUM; flags:cint);cdecl; external DLLUtilName;
function  BN_GENCB_call(cb:PBN_GENCB; a:cint; b:cint):cint;cdecl; external DLLUtilName;
function  BN_GENCB_new:PBN_GENCB;cdecl; external DLLUtilName;
procedure BN_GENCB_free(cb:PBN_GENCB);cdecl; external DLLUtilName;
//procedure BN_GENCB_set_old(gencb:PBN_GENCB; callback:procedure (para1:cint; para2:cint; para3:pointer); cb_arg:pointer);cdecl; external DLLUtilName;
procedure BN_GENCB_set(gencb:PBN_GENCB; callback:TCB_BN_GENCB_set; cb_arg:pointer);cdecl; external DLLUtilName;
function  BN_GENCB_get_arg(cb:PBN_GENCB):pointer;cdecl; external DLLUtilName;

type
 BN_ULONG=PtrUint;
 PBN_ULONG=^BN_ULONG;

const
      BN_prime_checks = 0;      

      BN_BYTES=SizeOf(PtrUint);

      BN_BITS2=(BN_BYTES * 8);
      BN_BITS =(BN_BITS2 * 2);
      BN_TBIT =(1 shl (BN_BITS2 - 1));

    function  BN_num_bytes(a : PBIGNUM) : cint;

function  BN_abs_is_word(a:PBIGNUM; w:BN_ULONG):cint;cdecl; external DLLUtilName;
function  BN_is_zero(a:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_is_one(a:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_is_word(a:PBIGNUM; w:BN_ULONG):cint;cdecl; external DLLUtilName;
function  BN_is_odd(a:PBIGNUM):cint;cdecl; external DLLUtilName;

    function  BN_one(a : PBIGNUM) : cint;

procedure BN_zero_ex(a:PBIGNUM);cdecl; external DLLUtilName;

    function  BN_zero(a : PBIGNUM) : cint;

function  BN_value_one:PBIGNUM;cdecl; external DLLUtilName;
function  BN_options:pbyte;cdecl; external DLLUtilName;
function  BN_CTX_new:PBN_CTX;cdecl; external DLLUtilName;
function  BN_CTX_secure_new:PBN_CTX;cdecl; external DLLUtilName;
procedure BN_CTX_free(c:PBN_CTX);cdecl; external DLLUtilName;
procedure BN_CTX_start(ctx:PBN_CTX);cdecl; external DLLUtilName;
function  BN_CTX_get(ctx:PBN_CTX):PBIGNUM;cdecl; external DLLUtilName;
procedure BN_CTX_end(ctx:PBN_CTX);cdecl; external DLLUtilName;
function  BN_rand(rnd:PBIGNUM; bits:cint; top:cint; bottom:cint):cint;cdecl; external DLLUtilName;
function  BN_pseudo_rand(rnd:PBIGNUM; bits:cint; top:cint; bottom:cint):cint;cdecl; external DLLUtilName;
function  BN_rand_range(rnd:PBIGNUM; range:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_pseudo_rand_range(rnd:PBIGNUM; range:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_num_bits(a:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_num_bits_word(l:BN_ULONG):cint;cdecl; external DLLUtilName;
function  BN_security_bits(L:cint; N:cint):cint;cdecl; external DLLUtilName;
function  BN_new:PBIGNUM;cdecl; external DLLUtilName;
function  BN_secure_new:PBIGNUM;cdecl; external DLLUtilName;
procedure BN_clear_free(a:PBIGNUM);cdecl; external DLLUtilName;
function  BN_copy(a:PBIGNUM; b:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
procedure BN_swap(a:PBIGNUM; b:PBIGNUM);cdecl; external DLLUtilName;
function  BN_bin2bn(s:pbyte; len:cint; ret:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_bn2bin(a:PBIGNUM; _to:pbyte):cint;cdecl; external DLLUtilName;
function  BN_bn2binpad(a:PBIGNUM; _to:pbyte; tolen:cint):cint;cdecl; external DLLUtilName;
function  BN_lebin2bn(s:pbyte; len:cint; ret:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_bn2lebinpad(a:PBIGNUM; _to:pbyte; tolen:cint):cint;cdecl; external DLLUtilName;
function  BN_mpi2bn(s:pbyte; len:cint; ret:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_bn2mpi(a:PBIGNUM; _to:pbyte):cint;cdecl; external DLLUtilName;
function  BN_sub(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_usub(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_uadd(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_add(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_mul(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_sqr(r:PBIGNUM; a:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
procedure BN_set_negative(b:PBIGNUM; n:cint);cdecl; external DLLUtilName;
function  BN_is_negative(b:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_div(dv:PBIGNUM; rem:PBIGNUM; m:PBIGNUM; d:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;

    function  BN_mod(rem,m,d : PBIGNUM;ctx : PBN_CTX) : cint;

function  BN_nnmod(r:PBIGNUM; m:PBIGNUM; d:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_add(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_add_quick(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; m:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_mod_sub(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_sub_quick(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; m:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_mod_mul(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_sqr(r:PBIGNUM; a:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_lshift1(r:PBIGNUM; a:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_lshift1_quick(r:PBIGNUM; a:PBIGNUM; m:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_mod_lshift(r:PBIGNUM; a:PBIGNUM; n:cint; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_lshift_quick(r:PBIGNUM; a:PBIGNUM; n:cint; m:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_mod_word(a:PBIGNUM; w:BN_ULONG):BN_ULONG;cdecl; external DLLUtilName;
function  BN_div_word(a:PBIGNUM; w:BN_ULONG):BN_ULONG;cdecl; external DLLUtilName;
function  BN_mul_word(a:PBIGNUM; w:BN_ULONG):cint;cdecl; external DLLUtilName;
function  BN_add_word(a:PBIGNUM; w:BN_ULONG):cint;cdecl; external DLLUtilName;
function  BN_sub_word(a:PBIGNUM; w:BN_ULONG):cint;cdecl; external DLLUtilName;
function  BN_set_word(a:PBIGNUM; w:BN_ULONG):cint;cdecl; external DLLUtilName;
function  BN_get_word(a:PBIGNUM):BN_ULONG;cdecl; external DLLUtilName;
function  BN_cmp(a:PBIGNUM; b:PBIGNUM):cint;cdecl; external DLLUtilName;
procedure BN_free(a:PBIGNUM);cdecl; external DLLUtilName;
function  BN_is_bit_set(a:PBIGNUM; n:cint):cint;cdecl; external DLLUtilName;
function  BN_lshift(r:PBIGNUM; a:PBIGNUM; n:cint):cint;cdecl; external DLLUtilName;
function  BN_lshift1(r:PBIGNUM; a:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_exp(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_exp(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_exp_mont(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX;
               m_ctx:PBN_MONT_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_exp_mont_consttime(rr:PBIGNUM; a:PBIGNUM; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX;
               in_mont:PBN_MONT_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_exp_mont_word(r:PBIGNUM; a:BN_ULONG; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX;
               m_ctx:PBN_MONT_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_exp2_mont(r:PBIGNUM; a1:PBIGNUM; p1:PBIGNUM; a2:PBIGNUM; p2:PBIGNUM;
               m:PBIGNUM; ctx:PBN_CTX; m_ctx:PBN_MONT_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_exp_simple(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mask_bits(a:PBIGNUM; n:cint):cint;cdecl; external DLLUtilName;
//function  BN_print_fp(fp:PFILE; a:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_print(bio:PBIO; a:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_reciprocal(r:PBIGNUM; m:PBIGNUM; len:cint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_rshift(r:PBIGNUM; a:PBIGNUM; n:cint):cint;cdecl; external DLLUtilName;
function  BN_rshift1(r:PBIGNUM; a:PBIGNUM):cint;cdecl; external DLLUtilName;
procedure BN_clear(a:PBIGNUM);cdecl; external DLLUtilName;
function  BN_dup(a:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_ucmp(a:PBIGNUM; b:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_set_bit(a:PBIGNUM; n:cint):cint;cdecl; external DLLUtilName;
function  BN_clear_bit(a:PBIGNUM; n:cint):cint;cdecl; external DLLUtilName;
function  BN_bn2hex(a:PBIGNUM):pbyte;cdecl; external DLLUtilName;
function  BN_bn2dec(a:PBIGNUM):pbyte;cdecl; external DLLUtilName;
function  BN_hex2bn(a:PPBIGNUM; str:pbyte):cint;cdecl; external DLLUtilName;
function  BN_dec2bn(a:PPBIGNUM; str:pbyte):cint;cdecl; external DLLUtilName;
function  BN_asc2bn(a:PPBIGNUM; str:pbyte):cint;cdecl; external DLLUtilName;
function  BN_gcd(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_kronecker(a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_inverse(ret:PBIGNUM; a:PBIGNUM; n:PBIGNUM; ctx:PBN_CTX):PBIGNUM;cdecl; external DLLUtilName;
function  BN_mod_sqrt(ret:PBIGNUM; a:PBIGNUM; n:PBIGNUM; ctx:PBN_CTX):PBIGNUM;cdecl; external DLLUtilName;
procedure BN_consttime_swap(swap:BN_ULONG; a:PBIGNUM; b:PBIGNUM; nwords:cint);cdecl; external DLLUtilName;
function  BN_is_prime_ex(p:PBIGNUM; nchecks:cint; ctx:PBN_CTX; cb:PBN_GENCB):cint;cdecl; external DLLUtilName;
function  BN_is_prime_fasttest_ex(p:PBIGNUM; nchecks:cint; ctx:PBN_CTX; do_trial_division:cint; cb:PBN_GENCB):cint;cdecl; external DLLUtilName;
function  BN_X931_generate_Xpq(Xp:PBIGNUM; Xq:PBIGNUM; nbits:cint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_X931_derive_prime_ex(p:PBIGNUM; p1:PBIGNUM; p2:PBIGNUM; Xp:PBIGNUM; Xp1:PBIGNUM;
               Xp2:PBIGNUM; e:PBIGNUM; ctx:PBN_CTX; cb:PBN_GENCB):cint;cdecl; external DLLUtilName;
function  BN_X931_generate_prime_ex(p:PBIGNUM; p1:PBIGNUM; p2:PBIGNUM; Xp1:PBIGNUM; Xp2:PBIGNUM;
               Xp:PBIGNUM; e:PBIGNUM; ctx:PBN_CTX; cb:PBN_GENCB):cint;cdecl; external DLLUtilName;
function  BN_MONT_CTX_new:PBN_MONT_CTX;cdecl; external DLLUtilName;
function  BN_mod_mul_montgomery(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; mont:PBN_MONT_CTX; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_to_montgomery(r:PBIGNUM; a:PBIGNUM; mont:PBN_MONT_CTX; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_from_montgomery(r:PBIGNUM; a:PBIGNUM; mont:PBN_MONT_CTX; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
procedure BN_MONT_CTX_free(mont:PBN_MONT_CTX);cdecl; external DLLUtilName;
function  BN_MONT_CTX_set(mont:PBN_MONT_CTX; _mod:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_MONT_CTX_copy(_to:PBN_MONT_CTX; from:PBN_MONT_CTX):PBN_MONT_CTX;cdecl; external DLLUtilName;
function  BN_MONT_CTX_set_locked(pmont:PPBN_MONT_CTX; lock:PCRYPTO_RWLOCK; _mod:PBIGNUM; ctx:PBN_CTX):PBN_MONT_CTX;cdecl; external DLLUtilName;

    const
      BN_BLINDING_NO_UPDATE = $00000001;
      BN_BLINDING_NO_RECREATE = $00000002;

type
 Tbn_mod_exp=function  (r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX; m_ctx:PBN_MONT_CTX):cint;cdecl;
 TBN_nist_mod_func=function  (r:PBIGNUM; a:PBIGNUM; field:PBIGNUM; ctx:PBN_CTX):cint;cdecl;

function  BN_BLINDING_new(A:PBIGNUM; Ai:PBIGNUM; _mod:PBIGNUM):PBN_BLINDING;cdecl; external DLLUtilName;
procedure BN_BLINDING_free(b:PBN_BLINDING);cdecl; external DLLUtilName;
function  BN_BLINDING_update(b:PBN_BLINDING; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_BLINDING_convert(n:PBIGNUM; b:PBN_BLINDING; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_BLINDING_invert(n:PBIGNUM; b:PBN_BLINDING; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_BLINDING_convert_ex(n:PBIGNUM; r:PBIGNUM; b:PBN_BLINDING; para4:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_BLINDING_invert_ex(n:PBIGNUM; r:PBIGNUM; b:PBN_BLINDING; para4:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_BLINDING_is_current_thread(b:PBN_BLINDING):cint;cdecl; external DLLUtilName;
procedure BN_BLINDING_set_current_thread(b:PBN_BLINDING);cdecl; external DLLUtilName;
function  BN_BLINDING_lock(b:PBN_BLINDING):cint;cdecl; external DLLUtilName;
function  BN_BLINDING_unlock(b:PBN_BLINDING):cint;cdecl; external DLLUtilName;
function  BN_BLINDING_get_flags(para1:PBN_BLINDING):culong;cdecl; external DLLUtilName;
procedure BN_BLINDING_set_flags(para1:PBN_BLINDING; para2:culong);cdecl; external DLLUtilName;
function  BN_BLINDING_create_param(b:PBN_BLINDING; e:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX; bn_mod_exp:Tbn_mod_exp; m_ctx:PBN_MONT_CTX):PBN_BLINDING;cdecl; external DLLUtilName;
procedure BN_RECP_CTX_free(recp:PBN_RECP_CTX);cdecl; external DLLUtilName;
function  BN_RECP_CTX_set(recp:PBN_RECP_CTX; rdiv:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_mul_reciprocal(r:PBIGNUM; x:PBIGNUM; y:PBIGNUM; recp:PBN_RECP_CTX; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_mod_exp_recp(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_div_recp(dv:PBIGNUM; rem:PBIGNUM; m:PBIGNUM; recp:PBN_RECP_CTX; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_add(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM):cint;cdecl; external DLLUtilName;

    function  BN_GF2m_sub(r,a,b : PBIGNUM) : cint;

function  BN_GF2m_mod(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_mul(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_sqr(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_inv(r:PBIGNUM; b:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_div(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_exp(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_sqrt(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_solve_quad(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;

    function  BN_GF2m_cmp(a,b : PBIGNUM) : cint;

function  BN_GF2m_mod_arr(r:PBIGNUM; a:PBIGNUM; p:pcint):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_mul_arr(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; p:pcint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_sqr_arr(r:PBIGNUM; a:PBIGNUM; p:pcint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_inv_arr(r:PBIGNUM; b:PBIGNUM; p:pcint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_div_arr(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; p:pcint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_exp_arr(r:PBIGNUM; a:PBIGNUM; b:PBIGNUM; p:pcint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_sqrt_arr(r:PBIGNUM; a:PBIGNUM; p:pcint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_mod_solve_quad_arr(r:PBIGNUM; a:PBIGNUM; p:pcint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_GF2m_poly2arr(a:PBIGNUM; p:pcint; max:cint):cint;cdecl; external DLLUtilName;
function  BN_GF2m_arr2poly(p:pcint; a:PBIGNUM):cint;cdecl; external DLLUtilName;
function  BN_nist_mod_192(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_nist_mod_224(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_nist_mod_256(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_nist_mod_384(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_nist_mod_521(r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_get0_nist_prime_192:PBIGNUM;cdecl; external DLLUtilName;
function  BN_get0_nist_prime_224:PBIGNUM;cdecl; external DLLUtilName;
function  BN_get0_nist_prime_256:PBIGNUM;cdecl; external DLLUtilName;
function  BN_get0_nist_prime_384:PBIGNUM;cdecl; external DLLUtilName;
function  BN_get0_nist_prime_521:PBIGNUM;cdecl; external DLLUtilName;
function  BN_nist_mod_func(p:PBIGNUM):TBN_nist_mod_func;cdecl; external DLLUtilName;
function  BN_generate_dsa_nonce(_out:PBIGNUM; range:PBIGNUM; priv:PBIGNUM; message:pbyte; message_len:size_t;
               ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  BN_get_rfc2409_prime_768(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_get_rfc2409_prime_1024(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_get_rfc3526_prime_1536(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_get_rfc3526_prime_2048(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_get_rfc3526_prime_3072(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_get_rfc3526_prime_4096(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_get_rfc3526_prime_6144(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  BN_get_rfc3526_prime_8192(bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;

function  BN_bntest_rand(rnd:PBIGNUM; bits:cint; top:cint; bottom:cint):cint;cdecl; external DLLUtilName;
function  ERR_load_BN_strings:cint;cdecl; external DLLUtilName;

    const
      BN_F_BNRAND = 127;      
      BN_F_BN_BLINDING_CONVERT_EX = 100;      
      BN_F_BN_BLINDING_CREATE_PARAM = 128;      
      BN_F_BN_BLINDING_INVERT_EX = 101;      
      BN_F_BN_BLINDING_NEW = 102;      
      BN_F_BN_BLINDING_UPDATE = 103;      
      BN_F_BN_BN2DEC = 104;      
      BN_F_BN_BN2HEX = 105;      
      BN_F_BN_COMPUTE_WNAF = 142;      
      BN_F_BN_CTX_GET = 116;      
      BN_F_BN_CTX_NEW = 106;      
      BN_F_BN_CTX_START = 129;      
      BN_F_BN_DIV = 107;      
      BN_F_BN_DIV_RECP = 130;      
      BN_F_BN_EXP = 123;      
      BN_F_BN_EXPAND_INTERNAL = 120;      
      BN_F_BN_GENCB_NEW = 143;      
      BN_F_BN_GENERATE_DSA_NONCE = 140;      
      BN_F_BN_GENERATE_PRIME_EX = 141;      
      BN_F_BN_GF2M_MOD = 131;      
      BN_F_BN_GF2M_MOD_EXP = 132;      
      BN_F_BN_GF2M_MOD_MUL = 133;      
      BN_F_BN_GF2M_MOD_SOLVE_QUAD = 134;      
      BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR = 135;      
      BN_F_BN_GF2M_MOD_SQR = 136;      
      BN_F_BN_GF2M_MOD_SQRT = 137;      
      BN_F_BN_LSHIFT = 145;      
      BN_F_BN_MOD_EXP2_MONT = 118;      
      BN_F_BN_MOD_EXP_MONT = 109;      
      BN_F_BN_MOD_EXP_MONT_CONSTTIME = 124;      
      BN_F_BN_MOD_EXP_MONT_WORD = 117;      
      BN_F_BN_MOD_EXP_RECP = 125;      
      BN_F_BN_MOD_EXP_SIMPLE = 126;      
      BN_F_BN_MOD_INVERSE = 110;      
      BN_F_BN_MOD_INVERSE_NO_BRANCH = 139;      
      BN_F_BN_MOD_LSHIFT_QUICK = 119;      
      BN_F_BN_MOD_SQRT = 121;      
      BN_F_BN_MPI2BN = 112;      
      BN_F_BN_NEW = 113;      
      BN_F_BN_RAND = 114;      
      BN_F_BN_RAND_RANGE = 122;      
      BN_F_BN_RSHIFT = 146;      
      BN_F_BN_SET_WORDS = 144;      
      BN_F_BN_USUB = 115;      
      BN_R_ARG2_LT_ARG3 = 100;      
      BN_R_BAD_RECIPROCAL = 101;      
      BN_R_BIGNUM_TOO_LONG = 114;      
      BN_R_BITS_TOO_SMALL = 118;      
      BN_R_CALLED_WITH_EVEN_MODULUS = 102;      
      BN_R_DIV_BY_ZERO = 103;      
      BN_R_ENCODING_ERROR = 104;      
      BN_R_EXPAND_ON_STATIC_BIGNUM_DATA = 105;      
      BN_R_INPUT_NOT_REDUCED = 110;      
      BN_R_INVALID_LENGTH = 106;      
      BN_R_INVALID_RANGE = 115;      
      BN_R_INVALID_SHIFT = 119;      
      BN_R_NOT_A_SQUARE = 111;      
      BN_R_NOT_INITIALIZED = 107;      
      BN_R_NO_INVERSE = 108;      
      BN_R_NO_SOLUTION = 116;      
      BN_R_PRIVATE_KEY_TOO_LARGE = 117;      
      BN_R_P_IS_NOT_PRIME = 112;      
      BN_R_TOO_MANY_ITERATIONS = 113;      
      BN_R_TOO_MANY_TEMPORARY_VARIABLES = 109;      
      V_ASN1_UNIVERSAL = $00;      
      V_ASN1_APPLICATION = $40;      
      V_ASN1_CONTEXT_SPECIFIC = $80;      
      V_ASN1_PRIVATE = $c0;      
      V_ASN1_CONSTRUCTED = $20;      
      V_ASN1_PRIMITIVE_TAG = $1f;      
      V_ASN1_PRIMATIVE_TAG = $1f;      
      V_ASN1_APP_CHOOSE = -(2);      
      V_ASN1_OTHER = -(3);      
      V_ASN1_ANY = -(4);      
      V_ASN1_UNDEF = -(1);      
      V_ASN1_EOC = 0;      
      V_ASN1_BOOLEAN = 1;      
      V_ASN1_INTEGER = 2;      
      V_ASN1_BIT_STRING = 3;      
      V_ASN1_OCTET_STRING = 4;      
      V_ASN1_NULL = 5;      
      V_ASN1_OBJECT = 6;      
      V_ASN1_OBJECT_DESCRIPTOR = 7;      
      V_ASN1_EXTERNAL = 8;      
      V_ASN1_REAL = 9;      
      V_ASN1_ENUMERATED = 10;      
      V_ASN1_UTF8STRING = 12;      
      V_ASN1_SEQUENCE = 16;      
      V_ASN1_SET = 17;      
      V_ASN1_NUMERICSTRING = 18;      
      V_ASN1_PRINTABLESTRING = 19;      
      V_ASN1_T61STRING = 20;      
      V_ASN1_TELETEXSTRING = 20;      
      V_ASN1_VIDEOTEXSTRING = 21;      
      V_ASN1_IA5STRING = 22;      
      V_ASN1_UTCTIME = 23;      
      V_ASN1_GENERALIZEDTIME = 24;      
      V_ASN1_GRAPHICSTRING = 25;      
      V_ASN1_ISO64STRING = 26;      
      V_ASN1_VISIBLESTRING = 26;      
      V_ASN1_GENERALSTRING = 27;      
      V_ASN1_UNIVERSALSTRING = 28;      
      V_ASN1_BMPSTRING = 30;      
      V_ASN1_NEG = $100;      
      V_ASN1_NEG_INTEGER = 2 or V_ASN1_NEG;      
      V_ASN1_NEG_ENUMERATED = 10 or V_ASN1_NEG;      
      B_ASN1_NUMERICSTRING = $0001;      
      B_ASN1_PRINTABLESTRING = $0002;      
      B_ASN1_T61STRING = $0004;      
      B_ASN1_TELETEXSTRING = $0004;      
      B_ASN1_VIDEOTEXSTRING = $0008;      
      B_ASN1_IA5STRING = $0010;      
      B_ASN1_GRAPHICSTRING = $0020;      
      B_ASN1_ISO64STRING = $0040;      
      B_ASN1_VISIBLESTRING = $0040;      
      B_ASN1_GENERALSTRING = $0080;      
      B_ASN1_UNIVERSALSTRING = $0100;      
      B_ASN1_OCTET_STRING = $0200;      
      B_ASN1_BIT_STRING = $0400;      
      B_ASN1_BMPSTRING = $0800;      
      B_ASN1_UNKNOWN = $1000;      
      B_ASN1_UTF8STRING = $2000;      
      B_ASN1_UTCTIME = $4000;      
      B_ASN1_GENERALIZEDTIME = $8000;      
      B_ASN1_SEQUENCE = $10000;      
      MBSTRING_FLAG = $1000;      
      MBSTRING_UTF8 = MBSTRING_FLAG;      
      MBSTRING_ASC = MBSTRING_FLAG or 1;      
      MBSTRING_BMP = MBSTRING_FLAG or 2;      
      MBSTRING_UNIV = MBSTRING_FLAG or 4;      
      SMIME_OLDMIME = $400;      
      SMIME_CRLFEOL = $800;      
      SMIME_STREAM = $1000;

    type
      PX509_algor= ^TX509_algor_st;
      TX509_algor_st = record
          algorithm : PASN1_OBJECT;
          parameter : PASN1_TYPE;
        end;
      PPX509_ALGOR=^PX509_ALGOR;

      Pstack_st_X509_ALGOR = ^Tstack_st_X509_ALGOR;
      Tstack_st_X509_ALGOR = record
          {undefined structure}
        end;


      Tsk_X509_ALGOR_compfunc = function  (a:PPX509_ALGOR; b:PPX509_ALGOR):cint;cdecl;

      Tsk_X509_ALGOR_freefunc = procedure (a:PX509_ALGOR);cdecl;

      Tsk_X509_ALGOR_copyfunc = function  (a:PX509_ALGOR):PX509_ALGOR;cdecl;

    const
      ASN1_STRING_FLAG_NDEF = $010;      
      ASN1_STRING_FLAG_CONT = $020;      
      ASN1_STRING_FLAG_MSTRING = $040;      
      ASN1_STRING_FLAG_EMBED = $080;

    type
      Pasn1_string= ^Tasn1_string_st;
      Tasn1_string_st = record
          length : cint;
          _type : cint;
          data : pbyte;
          flags : clong;
        end;

      PPASN1_STRING=^PASN1_STRING;

      PASN1_ENCODING= ^TASN1_ENCODING_st;
      TASN1_ENCODING_st = record
          enc : pbyte;
          len : clong;
          modified : cint;
        end;

    const
      ASN1_LONG_UNDEF = $7fffffff;      
      STABLE_FLAGS_MALLOC = $01;      
      STABLE_FLAGS_CLEAR = STABLE_FLAGS_MALLOC;      
      STABLE_NO_MASK = $02;      
      DIRSTRING_TYPE = ((B_ASN1_PRINTABLESTRING or B_ASN1_T61STRING) or B_ASN1_BMPSTRING) or B_ASN1_UTF8STRING;      
      PKCS9STRING_TYPE = DIRSTRING_TYPE or B_ASN1_IA5STRING;

    type
      Pasn1_string_table= ^Tasn1_string_table_st;
      Tasn1_string_table_st = record
          nid : cint;
          minsize : clong;
          maxsize : clong;
          mask : culong;
          flags : culong;
        end;

      TASN1_STRING_TABLE = Tasn1_string_table_st;
      PPASN1_STRING_TABLE =^PASN1_STRING_TABLE;
      Pstack_st_ASN1_STRING_TABLE = ^Tstack_st_ASN1_STRING_TABLE;
      Tstack_st_ASN1_STRING_TABLE = record
          {undefined structure}
        end;


      Tsk_ASN1_STRING_TABLE_compfunc = function  (a:PPASN1_STRING_TABLE; b:PPASN1_STRING_TABLE):cint;cdecl;

      Tsk_ASN1_STRING_TABLE_freefunc = procedure (a:PASN1_STRING_TABLE);cdecl;

      Tsk_ASN1_STRING_TABLE_copyfunc = function  (a:PASN1_STRING_TABLE):PASN1_STRING_TABLE;cdecl;

    const
      ub_common_name = 64;      
      ub_locality_name = 128;      
      ub_state_name = 128;      
      ub_organization_name = 64;      
      ub_organization_unit_name = 64;      
      ub_title = 64;      
      ub_email_address = 128;      

    type
      Pi2d_of_void = Pointer;

      PASN1_ITEM=^TASN1_ITEM;
      TASN1_ITEM=record
      end;

      PASN1_ITEM_EXP = ^TASN1_ITEM_EXP;
      TASN1_ITEM_EXP = TASN1_ITEM;

    function  ASN1_ITEM_ptr(iptr : longint) : longint; cdecl; external DLLUtilName;

    const
      ASN1_STRFLGS_ESC_2253 = 1;      
      ASN1_STRFLGS_ESC_CTRL = 2;      
      ASN1_STRFLGS_ESC_MSB = 4;      
      ASN1_STRFLGS_ESC_QUOTE = 8;      
      CHARTYPE_PRINTABLESTRING = $10;      
      CHARTYPE_FIRST_ESC_2253 = $20;      
      CHARTYPE_LAST_ESC_2253 = $40;      
      ASN1_STRFLGS_UTF8_CONVERT = $10;      
      ASN1_STRFLGS_IGNORE_TYPE = $20;      
      ASN1_STRFLGS_SHOW_TYPE = $40;      
      ASN1_STRFLGS_DUMP_ALL = $80;      
      ASN1_STRFLGS_DUMP_UNKNOWN = $100;      
      ASN1_STRFLGS_DUMP_DER = $200;      
      ASN1_STRFLGS_ESC_2254 = $400;      
      ASN1_STRFLGS_RFC2253 = ((((ASN1_STRFLGS_ESC_2253 or ASN1_STRFLGS_ESC_CTRL) or ASN1_STRFLGS_ESC_MSB) or ASN1_STRFLGS_UTF8_CONVERT) or ASN1_STRFLGS_DUMP_UNKNOWN) or ASN1_STRFLGS_DUMP_DER;      

    type
      Pstack_st_ASN1_INTEGER = ^Tstack_st_ASN1_INTEGER;
      Tstack_st_ASN1_INTEGER = record
          {undefined structure}
        end;

      PASN1_INTEGER=Pointer;
      PPASN1_INTEGER=^PASN1_INTEGER;

      PASN1_GENERALSTRING=Pointer;
      PPASN1_GENERALSTRING=^PASN1_GENERALSTRING;

      PASN1_UTF8STRING=Pointer;
      PPASN1_UTF8STRING=^PASN1_UTF8STRING;

      Tsk_ASN1_INTEGER_compfunc = function  (a:PPASN1_INTEGER; b:PPASN1_INTEGER):cint;cdecl;

      Tsk_ASN1_INTEGER_freefunc = procedure (a:PASN1_INTEGER);cdecl;

      Tsk_ASN1_INTEGER_copyfunc = function  (a:PASN1_INTEGER):PASN1_INTEGER;cdecl;

      Tsk_ASN1_GENERALSTRING_compfunc = function  (a:PPASN1_GENERALSTRING; b:PPASN1_GENERALSTRING):cint;cdecl;

      Tsk_ASN1_GENERALSTRING_freefunc = procedure (a:PASN1_GENERALSTRING);cdecl;

      Tsk_ASN1_GENERALSTRING_copyfunc = function  (a:PASN1_GENERALSTRING):PASN1_GENERALSTRING;cdecl;

      Tsk_ASN1_UTF8STRING_compfunc = function  (a:PPASN1_UTF8STRING; b:PPASN1_UTF8STRING):cint;cdecl;

      Tsk_ASN1_UTF8STRING_freefunc = procedure (a:PASN1_UTF8STRING);cdecl;

      Tsk_ASN1_UTF8STRING_copyfunc = function  (a:PASN1_UTF8STRING):PASN1_UTF8STRING;cdecl;

    type

      PASN1_SEQUENCE_ANY=Pointer;
      PPASN1_SEQUENCE_ANY=^PASN1_SEQUENCE_ANY;

      Pstack_st_ASN1_TYPE = ^Tstack_st_ASN1_TYPE;
      Tstack_st_ASN1_TYPE = record
          {undefined structure}
        end;


      Tsk_ASN1_TYPE_compfunc = function  (a:PPASN1_TYPE; b:PPASN1_TYPE):cint;cdecl;

      Tsk_ASN1_TYPE_freefunc = procedure (a:PASN1_TYPE);cdecl;

      Tsk_ASN1_TYPE_copyfunc = function  (a:PASN1_TYPE):PASN1_TYPE;cdecl;

function  d2i_ASN1_SEQUENCE_ANY(a:PPASN1_SEQUENCE_ANY; _in:Ppbyte; len:clong):PASN1_SEQUENCE_ANY;cdecl; external DLLUtilName;
function  i2d_ASN1_SEQUENCE_ANY(a:PASN1_SEQUENCE_ANY; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  d2i_ASN1_SET_ANY(a:PPASN1_SEQUENCE_ANY; _in:Ppbyte; len:clong):PASN1_SEQUENCE_ANY;cdecl; external DLLUtilName;
function  i2d_ASN1_SET_ANY(a:PASN1_SEQUENCE_ANY; _out:Ppbyte):cint;cdecl; external DLLUtilName;

    type

      PBIT_STRING_BITNAME= ^TBIT_STRING_BITNAME_st;
      TBIT_STRING_BITNAME_st = record
          bitnum : cint;
          lname : pbyte;
          sname : pbyte;
        end;
      TBIT_STRING_BITNAME = TBIT_STRING_BITNAME_st;

function  ASN1_TYPE_new:PASN1_TYPE;cdecl; external DLLUtilName;
procedure ASN1_TYPE_free(a:PASN1_TYPE);cdecl; external DLLUtilName;
function  d2i_ASN1_TYPE(a:PPASN1_TYPE; _in:Ppbyte; len:clong):PASN1_TYPE;cdecl; external DLLUtilName;
function  i2d_ASN1_TYPE(a:PASN1_TYPE; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_TYPE_get(a:PASN1_TYPE):cint;cdecl; external DLLUtilName;
procedure ASN1_TYPE_set(a:PASN1_TYPE; _type:cint; value:pointer);cdecl; external DLLUtilName;
function  ASN1_TYPE_set1(a:PASN1_TYPE; _type:cint; value:pointer):cint;cdecl; external DLLUtilName;
function  ASN1_TYPE_cmp(a:PASN1_TYPE; b:PASN1_TYPE):cint;cdecl; external DLLUtilName;
function  ASN1_TYPE_pack_sequence(it:PASN1_ITEM; s:pointer; t:PPASN1_TYPE):PASN1_TYPE;cdecl; external DLLUtilName;
function  ASN1_TYPE_unpack_sequence(it:PASN1_ITEM; t:PASN1_TYPE):pointer;cdecl; external DLLUtilName;
function  ASN1_OBJECT_new:PASN1_OBJECT;cdecl; external DLLUtilName;
procedure ASN1_OBJECT_free(a:PASN1_OBJECT);cdecl; external DLLUtilName;
function  i2d_ASN1_OBJECT(a:PASN1_OBJECT; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_ASN1_OBJECT(a:PPASN1_OBJECT; pp:Ppbyte; length:clong):PASN1_OBJECT;cdecl; external DLLUtilName;

    type
      Pstack_st_ASN1_OBJECT = ^Tstack_st_ASN1_OBJECT;
      Tstack_st_ASN1_OBJECT = record
          {undefined structure}
        end;


      Tsk_ASN1_OBJECT_compfunc = function  (a:PPASN1_OBJECT; b:PPASN1_OBJECT):cint;cdecl;

      Tsk_ASN1_OBJECT_freefunc = procedure (a:PASN1_OBJECT);cdecl;

      Tsk_ASN1_OBJECT_copyfunc = function  (a:PASN1_OBJECT):PASN1_OBJECT;cdecl;

      PASN1_ENUMERATED=Pointer;
      PPASN1_ENUMERATED=^PASN1_ENUMERATED;

      PASN1_ENUMERAPASN1_ENUMERATEDTED=Pointer;

      PASN1_UTCTIME=Pointer;
      PPASN1_UTCTIME=^PASN1_UTCTIME;
      PASN1_GENERALIZEDTIME=Pointer;
      PPASN1_GENERALIZEDTIME=^PASN1_GENERALIZEDTIME;
      PASN1_TIME=Pointer;
      PPASN1_TIME=^PASN1_TIME;
      PASN1_OCTET_STRING=Pointer;
      PPASN1_OCTET_STRING=^PASN1_OCTET_STRING;
      PASN1_VISIBLESTRING=Pointer;
      PPASN1_VISIBLESTRING=^PASN1_VISIBLESTRING;
      PASN1_UNIVERSALSTRING=Pointer;
      PPASN1_UNIVERSALSTRING=^PASN1_UNIVERSALSTRING;
      PPASN1_NULL=^PASN1_NULL;

procedure ASN1_STRING_free(a:PASN1_STRING);cdecl; external DLLUtilName;
procedure ASN1_STRING_clear_free(a:PASN1_STRING);cdecl; external DLLUtilName;
function  ASN1_STRING_copy(dst:PASN1_STRING; str:PASN1_STRING):cint;cdecl; external DLLUtilName;
function  ASN1_STRING_dup(a:PASN1_STRING):PASN1_STRING;cdecl; external DLLUtilName;
function  ASN1_STRING_type_new(_type:cint):PASN1_STRING;cdecl; external DLLUtilName;
function  ASN1_STRING_cmp(a:PASN1_STRING; b:PASN1_STRING):cint;cdecl; external DLLUtilName;
function  ASN1_STRING_set(str:PASN1_STRING; data:pointer; len:cint):cint;cdecl; external DLLUtilName;
procedure ASN1_STRING_set0(str:PASN1_STRING; data:pointer; len:cint);cdecl; external DLLUtilName;
function  ASN1_STRING_length(x:PASN1_STRING):cint;cdecl; external DLLUtilName;
procedure ASN1_STRING_length_set(x:PASN1_STRING; n:cint);cdecl; external DLLUtilName;
function  ASN1_STRING_type(x:PASN1_STRING):cint;cdecl; external DLLUtilName;
function  ASN1_BIT_STRING_new:PASN1_BIT_STRING;cdecl; external DLLUtilName;
procedure ASN1_BIT_STRING_free(a:PASN1_BIT_STRING);cdecl; external DLLUtilName;
function  d2i_ASN1_BIT_STRING(a:PPASN1_BIT_STRING; _in:Ppbyte; len:clong):PASN1_BIT_STRING;cdecl; external DLLUtilName;
function  i2d_ASN1_BIT_STRING(a:PASN1_BIT_STRING; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_BIT_STRING_set(a:PASN1_BIT_STRING; d:pbyte; length:cint):cint;cdecl; external DLLUtilName;
function  ASN1_BIT_STRING_set_bit(a:PASN1_BIT_STRING; n:cint; value:cint):cint;cdecl; external DLLUtilName;
function  ASN1_BIT_STRING_get_bit(a:PASN1_BIT_STRING; n:cint):cint;cdecl; external DLLUtilName;
function  ASN1_BIT_STRING_check(a:PASN1_BIT_STRING; flags:pbyte; flags_len:cint):cint;cdecl; external DLLUtilName;
function  ASN1_BIT_STRING_name_print(_out:PBIO; bs:PASN1_BIT_STRING; tbl:PBIT_STRING_BITNAME; indent:cint):cint;cdecl; external DLLUtilName;
function  ASN1_BIT_STRING_num_asc(name:pbyte; tbl:PBIT_STRING_BITNAME):cint;cdecl; external DLLUtilName;
function  ASN1_BIT_STRING_set_asc(bs:PASN1_BIT_STRING; name:pbyte; value:cint; tbl:PBIT_STRING_BITNAME):cint;cdecl; external DLLUtilName;
function  ASN1_INTEGER_new:PASN1_INTEGER;cdecl; external DLLUtilName;
procedure ASN1_INTEGER_free(a:PASN1_INTEGER);cdecl; external DLLUtilName;
function  d2i_ASN1_INTEGER(a:PPASN1_INTEGER; _in:Ppbyte; len:clong):PASN1_INTEGER;cdecl; external DLLUtilName;
function  i2d_ASN1_INTEGER(a:PASN1_INTEGER; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  d2i_ASN1_UINTEGER(a:PPASN1_INTEGER; pp:Ppbyte; length:clong):PASN1_INTEGER;cdecl; external DLLUtilName;
function  ASN1_INTEGER_dup(x:PASN1_INTEGER):PASN1_INTEGER;cdecl; external DLLUtilName;
function  ASN1_INTEGER_cmp(x:PASN1_INTEGER; y:PASN1_INTEGER):cint;cdecl; external DLLUtilName;
function  ASN1_ENUMERATED_new:PASN1_ENUMERAPASN1_ENUMERATEDTED;cdecl; external DLLUtilName;
procedure ASN1_ENUMERATED_free(a:PASN1_ENUMERATED);cdecl; external DLLUtilName;
function  d2i_ASN1_ENUMERATED(a:PPASN1_ENUMERATED; _in:Ppbyte; len:clong):PASN1_ENUMERATED;cdecl; external DLLUtilName;
function  i2d_ASN1_ENUMERATED(a:PASN1_ENUMERATED; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_UTCTIME_check(a:PASN1_UTCTIME):cint;cdecl; external DLLUtilName;
function  ASN1_UTCTIME_set(s:PASN1_UTCTIME; t:time_t):PASN1_UTCTIME;cdecl; external DLLUtilName;
function  ASN1_UTCTIME_adj(s:PASN1_UTCTIME; t:time_t; offset_day:cint; offset_sec:clong):PASN1_UTCTIME;cdecl; external DLLUtilName;
function  ASN1_UTCTIME_set_string(s:PASN1_UTCTIME; str:pbyte):cint;cdecl; external DLLUtilName;
function  ASN1_UTCTIME_cmp_time_t(s:PASN1_UTCTIME; t:time_t):cint;cdecl; external DLLUtilName;
function  ASN1_GENERALIZEDTIME_check(a:PASN1_GENERALIZEDTIME):cint;cdecl; external DLLUtilName;
function  ASN1_GENERALIZEDTIME_set(s:PASN1_GENERALIZEDTIME; t:time_t):PASN1_GENERALIZEDTIME;cdecl; external DLLUtilName;
function  ASN1_GENERALIZEDTIME_adj(s:PASN1_GENERALIZEDTIME; t:time_t; offset_day:cint; offset_sec:clong):PASN1_GENERALIZEDTIME;cdecl; external DLLUtilName;
function  ASN1_GENERALIZEDTIME_set_string(s:PASN1_GENERALIZEDTIME; str:pbyte):cint;cdecl; external DLLUtilName;
function  ASN1_TIME_diff(pday:pcint; psec:pcint; from:PASN1_TIME; _to:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  ASN1_OCTET_STRING_new:PASN1_OCTET_STRING;cdecl; external DLLUtilName;
procedure ASN1_OCTET_STRING_free(a:PASN1_OCTET_STRING);cdecl; external DLLUtilName;
function  d2i_ASN1_OCTET_STRING(a:PPASN1_OCTET_STRING; _in:Ppbyte; len:clong):PASN1_OCTET_STRING;cdecl; external DLLUtilName;
function  i2d_ASN1_OCTET_STRING(a:PASN1_OCTET_STRING; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_OCTET_STRING_dup(a:PASN1_OCTET_STRING):PASN1_OCTET_STRING;cdecl; external DLLUtilName;
function  ASN1_OCTET_STRING_cmp(a:PASN1_OCTET_STRING; b:PASN1_OCTET_STRING):cint;cdecl; external DLLUtilName;
function  ASN1_OCTET_STRING_set(str:PASN1_OCTET_STRING; data:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  ASN1_VISIBLESTRING_new:PASN1_VISIBLESTRING;cdecl; external DLLUtilName;
procedure ASN1_VISIBLESTRING_free(a:PASN1_VISIBLESTRING);cdecl; external DLLUtilName;
function  d2i_ASN1_VISIBLESTRING(a:PPASN1_VISIBLESTRING; _in:Ppbyte; len:clong):PASN1_VISIBLESTRING;cdecl; external DLLUtilName;
function  i2d_ASN1_VISIBLESTRING(a:PASN1_VISIBLESTRING; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_UNIVERSALSTRING_new:PASN1_UNIVERSALSTRING;cdecl; external DLLUtilName;
procedure ASN1_UNIVERSALSTRING_free(a:PASN1_UNIVERSALSTRING);cdecl; external DLLUtilName;
function  d2i_ASN1_UNIVERSALSTRING(a:PPASN1_UNIVERSALSTRING; _in:Ppbyte; len:clong):PASN1_UNIVERSALSTRING;cdecl; external DLLUtilName;
function  i2d_ASN1_UNIVERSALSTRING(a:PASN1_UNIVERSALSTRING; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_UTF8STRING_new:PASN1_UTF8STRING;cdecl; external DLLUtilName;
procedure ASN1_UTF8STRING_free(a:PASN1_UTF8STRING);cdecl; external DLLUtilName;
function  d2i_ASN1_UTF8STRING(a:PPASN1_UTF8STRING; _in:Ppbyte; len:clong):PASN1_UTF8STRING;cdecl; external DLLUtilName;
function  i2d_ASN1_UTF8STRING(a:PASN1_UTF8STRING; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_NULL_new:PASN1_NULL;cdecl; external DLLUtilName;
procedure ASN1_NULL_free(a:PASN1_NULL);cdecl; external DLLUtilName;
function  d2i_ASN1_NULL(a:PPASN1_NULL; _in:Ppbyte; len:clong):PASN1_NULL;cdecl; external DLLUtilName;
function  i2d_ASN1_NULL(a:PASN1_NULL; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_BMPSTRING_new:PASN1_BMPSTRING;cdecl; external DLLUtilName;
procedure ASN1_BMPSTRING_free(a:PASN1_BMPSTRING);cdecl; external DLLUtilName;
function  d2i_ASN1_BMPSTRING(a:PPASN1_BMPSTRING; _in:Ppbyte; len:clong):PASN1_BMPSTRING;cdecl; external DLLUtilName;
function  i2d_ASN1_BMPSTRING(a:PASN1_BMPSTRING; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  UTF8_getc(str:pbyte; len:cint; val:pculong):cint;cdecl; external DLLUtilName;
function  UTF8_putc(str:pbyte; len:cint; value:culong):cint;cdecl; external DLLUtilName;
function  ASN1_PRINTABLE_new:PASN1_STRING;cdecl; external DLLUtilName;
procedure ASN1_PRINTABLE_free(a:PASN1_STRING);cdecl; external DLLUtilName;
function  d2i_ASN1_PRINTABLE(a:PPASN1_STRING; _in:Ppbyte; len:clong):PASN1_STRING;cdecl; external DLLUtilName;
function  i2d_ASN1_PRINTABLE(a:PASN1_STRING; _out:Ppbyte):cint;cdecl; external DLLUtilName;

function  DIRECTORYSTRING_new:PASN1_STRING;cdecl; external DLLUtilName;
procedure DIRECTORYSTRING_free(a:PASN1_STRING);cdecl; external DLLUtilName;
function  d2i_DIRECTORYSTRING(a:PPASN1_STRING;_in:Ppbyte; len:clong):PASN1_STRING;cdecl; external DLLUtilName;
function  i2d_DIRECTORYSTRING(a:PASN1_STRING;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  DISPLAYTEXT_new:PASN1_STRING;cdecl; external DLLUtilName;
procedure DISPLAYTEXT_free(a:PASN1_STRING);cdecl; external DLLUtilName;
function  d2i_DISPLAYTEXT(a:PPASN1_STRING;_in:Ppbyte; len:clong):PASN1_STRING;cdecl; external DLLUtilName;
function  i2d_DISPLAYTEXT(a:PASN1_STRING;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_PRINTABLESTRING_new:PASN1_PRINTABLESTRING;cdecl; external DLLUtilName;
procedure ASN1_PRINTABLESTRING_free(a:PASN1_PRINTABLESTRING);cdecl; external DLLUtilName;
function  d2i_ASN1_PRINTABLESTRING(a:PPASN1_PRINTABLESTRING;_in:Ppbyte; len:clong):PASN1_PRINTABLESTRING;cdecl; external DLLUtilName;
function  i2d_ASN1_PRINTABLESTRING(a:PASN1_PRINTABLESTRING;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_T61STRING_new:PASN1_T61STRING;cdecl; external DLLUtilName;
procedure ASN1_T61STRING_free(a:PASN1_T61STRING);cdecl; external DLLUtilName;
function  d2i_ASN1_T61STRING(a:PPASN1_T61STRING;_in:Ppbyte; len:clong):PASN1_T61STRING;cdecl; external DLLUtilName;
function  i2d_ASN1_T61STRING(a:PASN1_T61STRING;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_IA5STRING_new:PASN1_IA5STRING;cdecl; external DLLUtilName;
procedure ASN1_IA5STRING_free(a:PASN1_IA5STRING);cdecl; external DLLUtilName;
function  d2i_ASN1_IA5STRING(a:PPASN1_IA5STRING;_in:Ppbyte; len:clong):PASN1_IA5STRING;cdecl; external DLLUtilName;
function  i2d_ASN1_IA5STRING(a:PASN1_IA5STRING;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_GENERALSTRING_new:PASN1_GENERALSTRING;cdecl; external DLLUtilName;
procedure ASN1_GENERALSTRING_free(a:PASN1_GENERALSTRING);cdecl; external DLLUtilName;
function  d2i_ASN1_GENERALSTRING(a:PPASN1_GENERALSTRING;_in:Ppbyte; len:clong):PASN1_GENERALSTRING;cdecl; external DLLUtilName;
function  i2d_ASN1_GENERALSTRING(a:PASN1_GENERALSTRING;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_UTCTIME_new:PASN1_UTCTIME;cdecl; external DLLUtilName;
procedure ASN1_UTCTIME_free(a:PASN1_UTCTIME);cdecl; external DLLUtilName;
function  d2i_ASN1_UTCTIME(a:PPASN1_UTCTIME;_in:Ppbyte; len:clong):PASN1_UTCTIME;cdecl; external DLLUtilName;
function  i2d_ASN1_UTCTIME(a:PASN1_UTCTIME;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_GENERALIZEDTIME_new:PASN1_GENERALIZEDTIME;cdecl; external DLLUtilName;
procedure ASN1_GENERALIZEDTIME_free(a:PASN1_GENERALIZEDTIME);cdecl; external DLLUtilName;
function  d2i_ASN1_GENERALIZEDTIME(a:PPASN1_GENERALIZEDTIME;_in:Ppbyte; len:clong):PASN1_GENERALIZEDTIME;cdecl; external DLLUtilName;
function  i2d_ASN1_GENERALIZEDTIME(a:PASN1_GENERALIZEDTIME;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_TIME_new:PASN1_TIME;cdecl; external DLLUtilName;
procedure ASN1_TIME_free(a:PASN1_TIME);cdecl; external DLLUtilName;
function  d2i_ASN1_TIME(a:PPASN1_TIME;_in:Ppbyte; len:clong):PASN1_TIME;cdecl; external DLLUtilName;
function  i2d_ASN1_TIME(a:PASN1_TIME;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  ASN1_TIME_set(s:PASN1_TIME; t:time_t):PASN1_TIME;cdecl; external DLLUtilName;
function  ASN1_TIME_adj(s:PASN1_TIME; t:time_t; offset_day:cint; offset_sec:clong):PASN1_TIME;cdecl; external DLLUtilName;
function  ASN1_TIME_check(t:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  ASN1_TIME_to_generalizedtime(t:PASN1_TIME;_out:PPASN1_GENERALIZEDTIME):PASN1_GENERALIZEDTIME;cdecl; external DLLUtilName;
function  ASN1_TIME_set_string(s:PASN1_TIME; str:pbyte):cint;cdecl; external DLLUtilName;
function  i2a_ASN1_INTEGER(bp:PBIO; a:PASN1_INTEGER):cint;cdecl; external DLLUtilName;
function  a2i_ASN1_INTEGER(bp:PBIO; bs:PASN1_INTEGER; buf:pbyte; size:cint):cint;cdecl; external DLLUtilName;
function  i2a_ASN1_ENUMERATED(bp:PBIO; a:PASN1_ENUMERATED):cint;cdecl; external DLLUtilName;
function  a2i_ASN1_ENUMERATED(bp:PBIO; bs:PASN1_ENUMERATED; buf:pbyte; size:cint):cint;cdecl; external DLLUtilName;
function  i2a_ASN1_OBJECT(bp:PBIO; a:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  a2i_ASN1_STRING(bp:PBIO; bs:PASN1_STRING; buf:pbyte; size:cint):cint;cdecl; external DLLUtilName;
function  i2a_ASN1_STRING(bp:PBIO; a:PASN1_STRING; _type:cint):cint;cdecl; external DLLUtilName;
function  i2t_ASN1_OBJECT(buf:pbyte; buf_len:cint; a:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  a2d_ASN1_OBJECT(_out:pbyte; olen:cint; buf:pbyte; num:cint):cint;cdecl; external DLLUtilName;
function  ASN1_OBJECT_create(nid:cint; data:pbyte; len:cint; sn:pbyte; ln:pbyte):PASN1_OBJECT;cdecl; external DLLUtilName;
function  ASN1_INTEGER_get_int64(pr:Pint64; a:PASN1_INTEGER):cint;cdecl; external DLLUtilName;
function  ASN1_INTEGER_set_int64(a:PASN1_INTEGER; r:int64):cint;cdecl; external DLLUtilName;
function  ASN1_INTEGER_get_uint64(pr:Puint64; a:PASN1_INTEGER):cint;cdecl; external DLLUtilName;
function  ASN1_INTEGER_set_uint64(a:PASN1_INTEGER; r:uint64):cint;cdecl; external DLLUtilName;
function  ASN1_INTEGER_set(a:PASN1_INTEGER; v:clong):cint;cdecl; external DLLUtilName;
function  ASN1_INTEGER_get(a:PASN1_INTEGER):clong;cdecl; external DLLUtilName;
function  BN_to_ASN1_INTEGER(bn:PBIGNUM; ai:PASN1_INTEGER):PASN1_INTEGER;cdecl; external DLLUtilName;
function  ASN1_INTEGER_to_BN(ai:PASN1_INTEGER; bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  ASN1_ENUMERATED_get_int64(pr:Pint64; a:PASN1_ENUMERATED):cint;cdecl; external DLLUtilName;
function  ASN1_ENUMERATED_set_int64(a:PASN1_ENUMERATED; r:int64):cint;cdecl; external DLLUtilName;
function  ASN1_ENUMERATED_set(a:PASN1_ENUMERATED; v:clong):cint;cdecl; external DLLUtilName;
function  ASN1_ENUMERATED_get(a:PASN1_ENUMERATED):clong;cdecl; external DLLUtilName;
function  BN_to_ASN1_ENUMERATED(bn:PBIGNUM; ai:PASN1_ENUMERATED):PASN1_ENUMERATED;cdecl; external DLLUtilName;
function  ASN1_ENUMERATED_to_BN(ai:PASN1_ENUMERATED; bn:PBIGNUM):PBIGNUM;cdecl; external DLLUtilName;
function  ASN1_PRINTABLE_type(s:pbyte; max:cint):cint;cdecl; external DLLUtilName;
function  ASN1_tag2bit(tag:cint):culong;cdecl; external DLLUtilName;
function  ASN1_get_object(pp:Ppbyte; plength:pclong; ptag:pcint; pclass:pcint; omax:clong):cint;cdecl; external DLLUtilName;
function  ASN1_check_infinite_end(p:Ppbyte; len:clong):cint;cdecl; external DLLUtilName;
function  ASN1_const_check_infinite_end(p:Ppbyte; len:clong):cint;cdecl; external DLLUtilName;
procedure ASN1_put_object(pp:Ppbyte; constructed:cint; length:cint; tag:cint; xclass:cint);cdecl; external DLLUtilName;
function  ASN1_put_eoc(pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  ASN1_object_size(constructed:cint; length:cint; tag:cint):cint;cdecl; external DLLUtilName;
function  ASN1_dup(i2d:Pi2d_of_void; d2i:Pd2i_of_void; x:pointer):pointer;cdecl; external DLLUtilName;

function  ASN1_item_dup(it:PASN1_ITEM; x:pointer):pointer;cdecl; external DLLUtilName;

//function  ASN1_d2i_fp(xnew:TPfunction; d2i:Pd2i_of_void;_in:PFILE; x:Ppointer):pointer;cdecl; external DLLUtilName;

//function  ASN1_item_d2i_fp(it:PASN1_ITEM;_in:PFILE; x:pointer):pointer;cdecl; external DLLUtilName;
//function  ASN1_i2d_fp(i2d:Pi2d_of_void;_out:PFILE; x:pointer):cint;cdecl; external DLLUtilName;
//function  ASN1_i2d_fp_of(_type,i2d,out,x : longint) : longint;

//function  ASN1_item_i2d_fp(it:PASN1_ITEM;_out:PFILE; x:pointer):cint;cdecl; external DLLUtilName;
//function  ASN1_STRING_print_ex_fp(fp:PFILE; str:PASN1_STRING; flags:culong):cint;cdecl; external DLLUtilName;
function  ASN1_STRING_to_UTF8(_out:Ppbyte;_in:PASN1_STRING):cint;cdecl; external DLLUtilName;
function  ASN1_d2i_bio(xnew:TPfunction; d2i:Pd2i_of_void;_in:PBIO; x:Ppointer):pointer;cdecl; external DLLUtilName;
//function  ASN1_d2i_bio_of(_type,xnew,d2i,in,x : longint) : Ptype;

function  ASN1_item_d2i_bio(it:PASN1_ITEM;_in:PBIO; x:pointer):pointer;cdecl; external DLLUtilName;
function  ASN1_i2d_bio(i2d:Pi2d_of_void;_out:PBIO; x:pbyte):cint;cdecl; external DLLUtilName;
//function  ASN1_i2d_bio_of(_type,i2d,out,x : longint) : longint;

function  ASN1_item_i2d_bio(it:PASN1_ITEM;_out:PBIO; x:pointer):cint;cdecl; external DLLUtilName;
function  ASN1_UTCTIME_print(fp:PBIO; a:PASN1_UTCTIME):cint;cdecl; external DLLUtilName;
function  ASN1_GENERALIZEDTIME_print(fp:PBIO; a:PASN1_GENERALIZEDTIME):cint;cdecl; external DLLUtilName;
function  ASN1_TIME_print(fp:PBIO; a:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  ASN1_STRING_print(bp:PBIO; v:PASN1_STRING):cint;cdecl; external DLLUtilName;
function  ASN1_STRING_print_ex(_out:PBIO; str:PASN1_STRING; flags:culong):cint;cdecl; external DLLUtilName;
function  ASN1_buf_print(bp:PBIO; buf:pbyte; buflen:size_t; off:cint):cint;cdecl; external DLLUtilName;
function  ASN1_bn_print(bp:PBIO; number:pbyte; num:PBIGNUM; buf:pbyte; off:cint):cint;cdecl; external DLLUtilName;
function  ASN1_parse(bp:PBIO; pp:pbyte; len:clong; indent:cint):cint;cdecl; external DLLUtilName;
function  ASN1_parse_dump(bp:PBIO; pp:pbyte; len:clong; indent:cint; dump:cint):cint;cdecl; external DLLUtilName;
function  ASN1_tag2str(tag:cint):pbyte;cdecl; external DLLUtilName;
function  ASN1_UNIVERSALSTRING_to_string(s:PASN1_UNIVERSALSTRING):cint;cdecl; external DLLUtilName;
function  ASN1_TYPE_set_octetstring(a:PASN1_TYPE; data:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  ASN1_TYPE_get_octetstring(a:PASN1_TYPE; data:pbyte; max_len:cint):cint;cdecl; external DLLUtilName;
function  ASN1_TYPE_set_int_octetstring(a:PASN1_TYPE; num:clong; data:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  ASN1_TYPE_get_int_octetstring(a:PASN1_TYPE; num:pclong; data:pbyte; max_len:cint):cint;cdecl; external DLLUtilName;
function  ASN1_item_unpack(oct:PASN1_STRING; it:PASN1_ITEM):pointer;cdecl; external DLLUtilName;
function  ASN1_item_pack(obj:pointer; it:PASN1_ITEM; oct:PPASN1_OCTET_STRING):PASN1_STRING;cdecl; external DLLUtilName;
procedure ASN1_STRING_set_default_mask(mask:culong);cdecl; external DLLUtilName;
function  ASN1_STRING_set_default_mask_asc(p:pbyte):cint;cdecl; external DLLUtilName;
function  ASN1_STRING_get_default_mask:culong;cdecl; external DLLUtilName;
function  ASN1_mbstring_copy(_out:PPASN1_STRING;_in:pbyte; len:cint; inform:cint; mask:culong):cint;cdecl; external DLLUtilName;
function  ASN1_mbstring_ncopy(_out:PPASN1_STRING;_in:pbyte; len:cint; inform:cint; mask:culong; 
               minsize:clong; maxsize:clong):cint;cdecl; external DLLUtilName;
function  ASN1_STRING_set_by_NID(_out:PPASN1_STRING;_in:pbyte; inlen:cint; inform:cint; nid:cint):PASN1_STRING;cdecl; external DLLUtilName;
function  ASN1_STRING_TABLE_get(nid:cint):PASN1_STRING_TABLE;cdecl; external DLLUtilName;
function  ASN1_STRING_TABLE_add(para1:cint; para2:clong; para3:clong; para4:culong; para5:culong):cint;cdecl; external DLLUtilName;
procedure ASN1_STRING_TABLE_cleanup;cdecl; external DLLUtilName;
function  ASN1_item_new(it:PASN1_ITEM):PASN1_VALUE;cdecl; external DLLUtilName;
procedure ASN1_item_free(val:PASN1_VALUE; it:PASN1_ITEM);cdecl; external DLLUtilName;
function  ASN1_item_d2i(val:PPASN1_VALUE;_in:Ppbyte; len:clong; it:PASN1_ITEM):PASN1_VALUE;cdecl; external DLLUtilName;
function  ASN1_item_i2d(val:PASN1_VALUE;_out:Ppbyte; it:PASN1_ITEM):cint;cdecl; external DLLUtilName;
function  ASN1_item_ndef_i2d(val:PASN1_VALUE;_out:Ppbyte; it:PASN1_ITEM):cint;cdecl; external DLLUtilName;
procedure ASN1_add_oid_module;cdecl; external DLLUtilName;
procedure ASN1_add_stable_module;cdecl; external DLLUtilName;
function  ASN1_generate_nconf(str:pbyte; nconf:PCONF):PASN1_TYPE;cdecl; external DLLUtilName;
function  ASN1_generate_v3(str:pbyte; cnf:PX509V3_CTX):PASN1_TYPE;cdecl; external DLLUtilName;
function  ASN1_str2mask(str:pbyte; pmask:pculong):cint;cdecl; external DLLUtilName;

    const
      ASN1_PCTX_FLAGS_SHOW_ABSENT = $001;      
      ASN1_PCTX_FLAGS_SHOW_SEQUENCE = $002;      
      ASN1_PCTX_FLAGS_SHOW_SSOF = $004;      
      ASN1_PCTX_FLAGS_SHOW_TYPE = $008;      
      ASN1_PCTX_FLAGS_NO_ANY_TYPE = $010;      
      ASN1_PCTX_FLAGS_NO_MSTRING_TYPE = $020;      
      ASN1_PCTX_FLAGS_NO_FIELD_NAME = $040;      
      ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME = $080;      
      ASN1_PCTX_FLAGS_NO_STRUCT_NAME = $100;      

type
 Tscan_cb=function  (ctx:PASN1_SCTX):cint; cdecl;

function  ASN1_item_print(_out:PBIO; ifld:PASN1_VALUE; indent:cint; it:PASN1_ITEM; pctx:PASN1_PCTX):cint;cdecl; external DLLUtilName;
function  ASN1_PCTX_new:PASN1_PCTX;cdecl; external DLLUtilName;
procedure ASN1_PCTX_free(p:PASN1_PCTX);cdecl; external DLLUtilName;
function  ASN1_PCTX_get_flags(p:PASN1_PCTX):culong;cdecl; external DLLUtilName;
procedure ASN1_PCTX_set_flags(p:PASN1_PCTX; flags:culong);cdecl; external DLLUtilName;
function  ASN1_PCTX_get_nm_flags(p:PASN1_PCTX):culong;cdecl; external DLLUtilName;
procedure ASN1_PCTX_set_nm_flags(p:PASN1_PCTX; flags:culong);cdecl; external DLLUtilName;
function  ASN1_PCTX_get_cert_flags(p:PASN1_PCTX):culong;cdecl; external DLLUtilName;
procedure ASN1_PCTX_set_cert_flags(p:PASN1_PCTX; flags:culong);cdecl; external DLLUtilName;
function  ASN1_PCTX_get_oid_flags(p:PASN1_PCTX):culong;cdecl; external DLLUtilName;
procedure ASN1_PCTX_set_oid_flags(p:PASN1_PCTX; flags:culong);cdecl; external DLLUtilName;
function  ASN1_PCTX_get_str_flags(p:PASN1_PCTX):culong;cdecl; external DLLUtilName;
procedure ASN1_PCTX_set_str_flags(p:PASN1_PCTX; flags:culong);cdecl; external DLLUtilName;
function  ASN1_SCTX_new(scan_cb:Tscan_cb):PASN1_SCTX;cdecl; external DLLUtilName;
procedure ASN1_SCTX_free(p:PASN1_SCTX);cdecl; external DLLUtilName;
function  ASN1_SCTX_get_item(p:PASN1_SCTX):PASN1_ITEM;cdecl; external DLLUtilName;
function  ASN1_SCTX_get_template(p:PASN1_SCTX):PASN1_TEMPLATE;cdecl; external DLLUtilName;
function  ASN1_SCTX_get_flags(p:PASN1_SCTX):culong;cdecl; external DLLUtilName;
procedure ASN1_SCTX_set_app_data(p:PASN1_SCTX; data:pointer);cdecl; external DLLUtilName;
function  ASN1_SCTX_get_app_data(p:PASN1_SCTX):pointer;cdecl; external DLLUtilName;
function  BIO_f_asn1:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_new_NDEF(_out:PBIO; val:PASN1_VALUE; it:PASN1_ITEM):PBIO;cdecl; external DLLUtilName;
function  i2d_ASN1_bio_stream(_out:PBIO; val:PASN1_VALUE;_in:PBIO; flags:cint; it:PASN1_ITEM):cint;cdecl; external DLLUtilName;
function  PEM_write_bio_ASN1_stream(_out:PBIO; val:PASN1_VALUE;_in:PBIO; flags:cint; hdr:pbyte; 
               it:PASN1_ITEM):cint;cdecl; external DLLUtilName;
function  SMIME_write_ASN1(bio:PBIO; val:PASN1_VALUE; data:PBIO; flags:cint; ctype_nid:cint; 
               econt_nid:cint; mdalgs:Pstack_st_X509_ALGOR; it:PASN1_ITEM):cint;cdecl; external DLLUtilName;
function  SMIME_read_ASN1(bio:PBIO; bcont:PPBIO; it:PASN1_ITEM):PASN1_VALUE;cdecl; external DLLUtilName;
function  SMIME_crlf_copy(_in:PBIO;_out:PBIO; flags:cint):cint;cdecl; external DLLUtilName;
function  SMIME_text(_in:PBIO;_out:PBIO):cint;cdecl; external DLLUtilName;
function  ERR_load_ASN1_strings:cint;cdecl; external DLLUtilName;

    const
      ASN1_F_A2D_ASN1_OBJECT = 100;      
      ASN1_F_A2I_ASN1_INTEGER = 102;      
      ASN1_F_A2I_ASN1_STRING = 103;      
      ASN1_F_APPEND_EXP = 176;      
      ASN1_F_ASN1_BIT_STRING_SET_BIT = 183;      
      ASN1_F_ASN1_CB = 177;      
      ASN1_F_ASN1_CHECK_TLEN = 104;      
      ASN1_F_ASN1_COLLECT = 106;      
      ASN1_F_ASN1_D2I_EX_PRIMITIVE = 108;      
      ASN1_F_ASN1_D2I_FP = 109;      
      ASN1_F_ASN1_D2I_READ_BIO = 107;      
      ASN1_F_ASN1_DIGEST = 184;      
      ASN1_F_ASN1_DO_ADB = 110;      
      ASN1_F_ASN1_DO_LOCK = 233;      
      ASN1_F_ASN1_DUP = 111;      
      ASN1_F_ASN1_EX_C2I = 204;      
      ASN1_F_ASN1_FIND_END = 190;      
      ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 216;      
      ASN1_F_ASN1_GENERATE_V3 = 178;      
      ASN1_F_ASN1_GET_INT64 = 224;      
      ASN1_F_ASN1_GET_OBJECT = 114;      
      ASN1_F_ASN1_GET_UINT64 = 225;      
      ASN1_F_ASN1_I2D_BIO = 116;      
      ASN1_F_ASN1_I2D_FP = 117;      
      ASN1_F_ASN1_ITEM_D2I_FP = 206;      
      ASN1_F_ASN1_ITEM_DUP = 191;      
      ASN1_F_ASN1_ITEM_EMBED_D2I = 120;      
      ASN1_F_ASN1_ITEM_EMBED_NEW = 121;      
      ASN1_F_ASN1_ITEM_I2D_BIO = 192;      
      ASN1_F_ASN1_ITEM_I2D_FP = 193;      
      ASN1_F_ASN1_ITEM_PACK = 198;      
      ASN1_F_ASN1_ITEM_SIGN = 195;      
      ASN1_F_ASN1_ITEM_SIGN_CTX = 220;      
      ASN1_F_ASN1_ITEM_UNPACK = 199;      
      ASN1_F_ASN1_ITEM_VERIFY = 197;      
      ASN1_F_ASN1_MBSTRING_NCOPY = 122;      
      ASN1_F_ASN1_OBJECT_NEW = 123;      
      ASN1_F_ASN1_OUTPUT_DATA = 214;      
      ASN1_F_ASN1_PCTX_NEW = 205;      
      ASN1_F_ASN1_SCTX_NEW = 221;      
      ASN1_F_ASN1_SIGN = 128;      
      ASN1_F_ASN1_STR2TYPE = 179;      
      ASN1_F_ASN1_STRING_GET_INT64 = 227;      
      ASN1_F_ASN1_STRING_GET_UINT64 = 230;      
      ASN1_F_ASN1_STRING_SET = 186;      
      ASN1_F_ASN1_STRING_TABLE_ADD = 129;      
      ASN1_F_ASN1_STRING_TO_BN = 228;      
      ASN1_F_ASN1_STRING_TYPE_NEW = 130;      
      ASN1_F_ASN1_TEMPLATE_EX_D2I = 132;      
      ASN1_F_ASN1_TEMPLATE_NEW = 133;      
      ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 131;      
      ASN1_F_ASN1_TIME_ADJ = 217;      
      ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 134;      
      ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 135;      
      ASN1_F_ASN1_UTCTIME_ADJ = 218;      
      ASN1_F_ASN1_VERIFY = 137;      
      ASN1_F_B64_READ_ASN1 = 209;      
      ASN1_F_B64_WRITE_ASN1 = 210;      
      ASN1_F_BIO_NEW_NDEF = 208;      
      ASN1_F_BITSTR_CB = 180;      
      ASN1_F_BN_TO_ASN1_STRING = 229;      
      ASN1_F_C2I_ASN1_BIT_STRING = 189;      
      ASN1_F_C2I_ASN1_INTEGER = 194;      
      ASN1_F_C2I_ASN1_OBJECT = 196;      
      ASN1_F_C2I_IBUF = 226;      
      ASN1_F_C2I_UINT64_INT = 101;      
      ASN1_F_COLLECT_DATA = 140;      
      ASN1_F_D2I_ASN1_OBJECT = 147;      
      ASN1_F_D2I_ASN1_UINTEGER = 150;      
      ASN1_F_D2I_AUTOPRIVATEKEY = 207;      
      ASN1_F_D2I_PRIVATEKEY = 154;      
      ASN1_F_D2I_PUBLICKEY = 155;      
      ASN1_F_DO_TCREATE = 222;      
      ASN1_F_I2D_ASN1_BIO_STREAM = 211;      
      ASN1_F_I2D_DSA_PUBKEY = 161;      
      ASN1_F_I2D_EC_PUBKEY = 181;      
      ASN1_F_I2D_PRIVATEKEY = 163;      
      ASN1_F_I2D_PUBLICKEY = 164;      
      ASN1_F_I2D_RSA_PUBKEY = 165;      
      ASN1_F_LONG_C2I = 166;      
      ASN1_F_OID_MODULE_INIT = 174;      
      ASN1_F_PARSE_TAGGING = 182;      
      ASN1_F_PKCS5_PBE2_SET_IV = 167;      
      ASN1_F_PKCS5_PBE2_SET_SCRYPT = 231;      
      ASN1_F_PKCS5_PBE_SET = 202;      
      ASN1_F_PKCS5_PBE_SET0_ALGOR = 215;      
      ASN1_F_PKCS5_PBKDF2_SET = 219;      
      ASN1_F_PKCS5_SCRYPT_SET = 232;      
      ASN1_F_SMIME_READ_ASN1 = 212;      
      ASN1_F_SMIME_TEXT = 213;      
      ASN1_F_STBL_MODULE_INIT = 223;      
      ASN1_F_UINT32_C2I = 105;      
      ASN1_F_UINT64_C2I = 112;      
      ASN1_F_X509_CRL_ADD0_REVOKED = 169;      
      ASN1_F_X509_INFO_NEW = 170;      
      ASN1_F_X509_NAME_ENCODE = 203;      
      ASN1_F_X509_NAME_EX_D2I = 158;      
      ASN1_F_X509_NAME_EX_NEW = 171;      
      ASN1_F_X509_PKEY_NEW = 173;      
      ASN1_R_ADDING_OBJECT = 171;      
      ASN1_R_ASN1_PARSE_ERROR = 203;      
      ASN1_R_ASN1_SIG_PARSE_ERROR = 204;      
      ASN1_R_AUX_ERROR = 100;      
      ASN1_R_BAD_OBJECT_HEADER = 102;      
      ASN1_R_BMPSTRING_IS_WRONG_LENGTH = 214;      
      ASN1_R_BN_LIB = 105;      
      ASN1_R_BOOLEAN_IS_WRONG_LENGTH = 106;      
      ASN1_R_BUFFER_TOO_SMALL = 107;      
      ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 108;      
      ASN1_R_CONTEXT_NOT_INITIALISED = 217;      
      ASN1_R_DATA_IS_WRONG = 109;      
      ASN1_R_DECODE_ERROR = 110;      
      ASN1_R_DEPTH_EXCEEDED = 174;      
      ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED = 198;      
      ASN1_R_ENCODE_ERROR = 112;      
      ASN1_R_ERROR_GETTING_TIME = 173;      
      ASN1_R_ERROR_LOADING_SECTION = 172;      
      ASN1_R_ERROR_SETTING_CIPHER_PARAMS = 114;      
      ASN1_R_EXPECTING_AN_INTEGER = 115;      
      ASN1_R_EXPECTING_AN_OBJECT = 116;      
      ASN1_R_EXPLICIT_LENGTH_MISMATCH = 119;      
      ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED = 120;      
      ASN1_R_FIELD_MISSING = 121;      
      ASN1_R_FIRST_NUM_TOO_LARGE = 122;      
      ASN1_R_HEADER_TOO_LONG = 123;      
      ASN1_R_ILLEGAL_BITSTRING_FORMAT = 175;      
      ASN1_R_ILLEGAL_BOOLEAN = 176;      
      ASN1_R_ILLEGAL_CHARACTERS = 124;      
      ASN1_R_ILLEGAL_FORMAT = 177;      
      ASN1_R_ILLEGAL_HEX = 178;      
      ASN1_R_ILLEGAL_IMPLICIT_TAG = 179;      
      ASN1_R_ILLEGAL_INTEGER = 180;      
      ASN1_R_ILLEGAL_NEGATIVE_VALUE = 226;      
      ASN1_R_ILLEGAL_NESTED_TAGGING = 181;      
      ASN1_R_ILLEGAL_NULL = 125;      
      ASN1_R_ILLEGAL_NULL_VALUE = 182;      
      ASN1_R_ILLEGAL_OBJECT = 183;      
      ASN1_R_ILLEGAL_OPTIONAL_ANY = 126;      
      ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE = 170;      
      ASN1_R_ILLEGAL_PADDING = 221;      
      ASN1_R_ILLEGAL_TAGGED_ANY = 127;      
      ASN1_R_ILLEGAL_TIME_VALUE = 184;      
      ASN1_R_ILLEGAL_ZERO_CONTENT = 222;      
      ASN1_R_INTEGER_NOT_ASCII_FORMAT = 185;      
      ASN1_R_INTEGER_TOO_LARGE_FOR_LONG = 128;      
      ASN1_R_INVALID_BIT_STRING_BITS_LEFT = 220;      
      ASN1_R_INVALID_BMPSTRING_LENGTH = 129;      
      ASN1_R_INVALID_DIGIT = 130;      
      ASN1_R_INVALID_MIME_TYPE = 205;      
      ASN1_R_INVALID_MODIFIER = 186;      
      ASN1_R_INVALID_NUMBER = 187;      
      ASN1_R_INVALID_OBJECT_ENCODING = 216;      
      ASN1_R_INVALID_SCRYPT_PARAMETERS = 227;      
      ASN1_R_INVALID_SEPARATOR = 131;      
      ASN1_R_INVALID_STRING_TABLE_VALUE = 218;      
      ASN1_R_INVALID_UNIVERSALSTRING_LENGTH = 133;      
      ASN1_R_INVALID_UTF8STRING = 134;      
      ASN1_R_INVALID_VALUE = 219;      
      ASN1_R_LIST_ERROR = 188;      
      ASN1_R_MIME_NO_CONTENT_TYPE = 206;      
      ASN1_R_MIME_PARSE_ERROR = 207;      
      ASN1_R_MIME_SIG_PARSE_ERROR = 208;      
      ASN1_R_MISSING_EOC = 137;      
      ASN1_R_MISSING_SECOND_NUMBER = 138;      
      ASN1_R_MISSING_VALUE = 189;      
      ASN1_R_MSTRING_NOT_UNIVERSAL = 139;      
      ASN1_R_MSTRING_WRONG_TAG = 140;      
      ASN1_R_NESTED_ASN1_STRING = 197;      
      ASN1_R_NON_HEX_CHARACTERS = 141;      
      ASN1_R_NOT_ASCII_FORMAT = 190;      
      ASN1_R_NOT_ENOUGH_DATA = 142;      
      ASN1_R_NO_CONTENT_TYPE = 209;      
      ASN1_R_NO_MATCHING_CHOICE_TYPE = 143;      
      ASN1_R_NO_MULTIPART_BODY_FAILURE = 210;      
      ASN1_R_NO_MULTIPART_BOUNDARY = 211;      
      ASN1_R_NO_SIG_CONTENT_TYPE = 212;      
      ASN1_R_NULL_IS_WRONG_LENGTH = 144;      
      ASN1_R_OBJECT_NOT_ASCII_FORMAT = 191;      
      ASN1_R_ODD_NUMBER_OF_CHARS = 145;      
      ASN1_R_SECOND_NUMBER_TOO_LARGE = 147;      
      ASN1_R_SEQUENCE_LENGTH_MISMATCH = 148;      
      ASN1_R_SEQUENCE_NOT_CONSTRUCTED = 149;      
      ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG = 192;      
      ASN1_R_SHORT_LINE = 150;      
      ASN1_R_SIG_INVALID_MIME_TYPE = 213;      
      ASN1_R_STREAMING_NOT_SUPPORTED = 202;      
      ASN1_R_STRING_TOO_LONG = 151;      
      ASN1_R_STRING_TOO_SHORT = 152;      
      ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 154;      
      ASN1_R_TIME_NOT_ASCII_FORMAT = 193;      
      ASN1_R_TOO_LARGE = 223;      
      ASN1_R_TOO_LONG = 155;      
      ASN1_R_TOO_SMALL = 224;      
      ASN1_R_TYPE_NOT_CONSTRUCTED = 156;      
      ASN1_R_TYPE_NOT_PRIMITIVE = 195;      
      ASN1_R_UNEXPECTED_EOC = 159;      
      ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH = 215;      
      ASN1_R_UNKNOWN_FORMAT = 160;      
      ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM = 161;      
      ASN1_R_UNKNOWN_OBJECT_TYPE = 162;      
      ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE = 163;      
      ASN1_R_UNKNOWN_SIGNATURE_ALGORITHM = 199;      
      ASN1_R_UNKNOWN_TAG = 194;      
      ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE = 164;      
      ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE = 167;      
      ASN1_R_UNSUPPORTED_TYPE = 196;      
      ASN1_R_WRONG_INTEGER_TYPE = 225;      
      ASN1_R_WRONG_PUBLIC_KEY_TYPE = 200;      
      ASN1_R_WRONG_TAG = 168;      
      OBJ_NAME_TYPE_UNDEF = $00;      
      OBJ_NAME_TYPE_MD_METH = $01;      
      OBJ_NAME_TYPE_CIPHER_METH = $02;      
      OBJ_NAME_TYPE_PKEY_METH = $03;      
      OBJ_NAME_TYPE_COMP_METH = $04;      
      OBJ_NAME_TYPE_NUM = $05;      
      OBJ_NAME_ALIAS = $8000;      
      OBJ_BSEARCH_VALUE_ON_NOMATCH = $01;      
      OBJ_BSEARCH_FIRST_VALUE_ON_MATCH = $02;

    type
      Pobj_name= ^Tobj_name_st;
      Tobj_name_st = record
          _type : cint;
          alias : cint;
          name : pbyte;
          data : pbyte;
        end;
      TOBJ_NAME = Tobj_name_st;

      Thash_func=function  (para1:pbyte):culong;cdecl;
      Tcmp_func=function  (para1:pbyte; para2:pbyte):cint;cdecl;
      Tfree_func=procedure (para1:pbyte; para2:cint; para3:pbyte);cdecl;
      TOBJ_NAME_do_all_fn=procedure (para1:POBJ_NAME; arg:pointer);cdecl;

    function  OBJ_create_and_add_object(a,b,c : pbyte) : cint;

function  OBJ_NAME_init:cint;cdecl; external DLLUtilName;
function  OBJ_NAME_new_index(hash_func:Thash_func; cmp_func:Tcmp_func; free_func:Tfree_func):cint;cdecl; external DLLUtilName;
function  OBJ_NAME_get(name:pbyte; _type:cint):pbyte;cdecl; external DLLUtilName;
function  OBJ_NAME_add(name:pbyte; _type:cint; data:pbyte):cint;cdecl; external DLLUtilName;
function  OBJ_NAME_remove(name:pbyte; _type:cint):cint;cdecl; external DLLUtilName;
procedure OBJ_NAME_cleanup(_type:cint);cdecl; external DLLUtilName;
procedure OBJ_NAME_do_all(_type:cint; fn:TOBJ_NAME_do_all_fn; arg:pointer);cdecl; external DLLUtilName;
procedure OBJ_NAME_do_all_sorted(_type:cint; fn:TOBJ_NAME_do_all_fn; arg:pointer);cdecl; external DLLUtilName;
function  OBJ_dup(o:PASN1_OBJECT):PASN1_OBJECT;cdecl; external DLLUtilName;
function  OBJ_nid2obj(n:cint):PASN1_OBJECT;cdecl; external DLLUtilName;
function  OBJ_nid2ln(n:cint):pbyte;cdecl; external DLLUtilName;
function  OBJ_nid2sn(n:cint):pbyte;cdecl; external DLLUtilName;
function  OBJ_obj2nid(o:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  OBJ_txt2obj(s:pbyte; no_name:cint):PASN1_OBJECT;cdecl; external DLLUtilName;
function  OBJ_obj2txt(buf:pbyte; buf_len:cint; a:PASN1_OBJECT; no_name:cint):cint;cdecl; external DLLUtilName;
function  OBJ_txt2nid(s:pbyte):cint;cdecl; external DLLUtilName;
function  OBJ_ln2nid(s:pbyte):cint;cdecl; external DLLUtilName;
function  OBJ_sn2nid(s:pbyte):cint;cdecl; external DLLUtilName;
function  OBJ_cmp(a:PASN1_OBJECT; b:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  OBJ_bsearch_(key:pointer; base:pointer; num:cint; size:cint; cmp:Tcmp_func):pointer;cdecl; external DLLUtilName;
function  OBJ_bsearch_ex_(key:pointer; base:pointer; num:cint; size:cint; cmp:Tcmp_func;
               flags:cint):pointer;cdecl; external DLLUtilName;

function  OBJ_new_nid(num:cint):cint;cdecl; external DLLUtilName;
function  OBJ_add_object(obj:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  OBJ_create(oid:pbyte; sn:pbyte; ln:pbyte):cint;cdecl; external DLLUtilName;
function  OBJ_create_objects(_in:PBIO):cint;cdecl; external DLLUtilName;
function  OBJ_length(obj:PASN1_OBJECT):size_t;cdecl; external DLLUtilName;
function  OBJ_get0_data(obj:PASN1_OBJECT):pbyte;cdecl; external DLLUtilName;
function  OBJ_find_sigid_algs(signid:cint; pdig_nid:pcint; ppkey_nid:pcint):cint;cdecl; external DLLUtilName;
function  OBJ_find_sigid_by_algs(psignid:pcint; dig_nid:cint; pkey_nid:cint):cint;cdecl; external DLLUtilName;
function  OBJ_add_sigid(signid:cint; dig_id:cint; pkey_id:cint):cint;cdecl; external DLLUtilName;
procedure OBJ_sigid_free;cdecl; external DLLUtilName;
function  ERR_load_OBJ_strings:cint;cdecl; external DLLUtilName;

    const
      OBJ_F_OBJ_ADD_OBJECT = 105;      
      OBJ_F_OBJ_CREATE = 100;      
      OBJ_F_OBJ_DUP = 101;      
      OBJ_F_OBJ_NAME_NEW_INDEX = 106;      
      OBJ_F_OBJ_NID2LN = 102;      
      OBJ_F_OBJ_NID2OBJ = 103;      
      OBJ_F_OBJ_NID2SN = 104;      
      OBJ_R_OID_EXISTS = 102;      
      OBJ_R_UNKNOWN_NID = 101;      
      EVP_PK_RSA = $0001;      
      EVP_PK_DSA = $0002;      
      EVP_PK_DH = $0004;      
      EVP_PK_EC = $0008;      
      EVP_PKT_SIGN = $0010;      
      EVP_PKT_ENC = $0020;      
      EVP_PKT_EXCH = $0040;      
      EVP_PKS_RSA = $0100;      
      EVP_PKS_DSA = $0200;      
      EVP_PKS_EC = $0400;      
      EVP_PKEY_NONE = NID_undef;      
      EVP_PKEY_RSA = NID_rsaEncryption;      
      EVP_PKEY_RSA2 = NID_rsa;      
      EVP_PKEY_DSA = NID_dsa;      
      EVP_PKEY_DSA1 = NID_dsa_2;      
      EVP_PKEY_DSA2 = NID_dsaWithSHA;      
      EVP_PKEY_DSA3 = NID_dsaWithSHA1;      
      EVP_PKEY_DSA4 = NID_dsaWithSHA1_2;      
      EVP_PKEY_DH = NID_dhKeyAgreement;      
      EVP_PKEY_DHX = NID_dhpublicnumber;      
      EVP_PKEY_EC = NID_X9_62_id_ecPublicKey;      
      EVP_PKEY_HMAC = NID_hmac;      
      EVP_PKEY_CMAC = NID_cmac;      
      EVP_PKEY_TLS1_PRF = NID_tls1_prf;      
      EVP_PKEY_HKDF = NID_hkdf;      
      EVP_PKEY_MO_SIGN = $0001;      
      EVP_PKEY_MO_VERIFY = $0002;      
      EVP_PKEY_MO_ENCRYPT = $0004;      
      EVP_PKEY_MO_DECRYPT = $0008;      

type
 TEVP_MD_init_cb=function  (ctx:PEVP_MD_CTX):cint;cdecl;
 TEVP_MD_update_cb=function  (ctx:PEVP_MD_CTX; data:pointer; count:size_t):cint;cdecl;
 TEVP_MD_final_cb=function  (ctx:PEVP_MD_CTX; md:pbyte):cint;cdecl;
 TEVP_MD_copy_cb=function  (_to:PEVP_MD_CTX; from:PEVP_MD_CTX):cint;cdecl;
 TEVP_MD_ctrl_cb=function  (ctx:PEVP_MD_CTX; cmd:cint; p1:cint; p2:pointer):cint;cdecl;

function  EVP_MD_meth_new(md_type:cint; pkey_type:cint):PEVP_MD;cdecl; external DLLUtilName;
function  EVP_MD_meth_dup(md:PEVP_MD):PEVP_MD;cdecl; external DLLUtilName;
procedure EVP_MD_meth_free(md:PEVP_MD);cdecl; external DLLUtilName;
function  EVP_MD_meth_set_input_blocksize(md:PEVP_MD; blocksize:cint):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_result_size(md:PEVP_MD; resultsize:cint):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_app_datasize(md:PEVP_MD; datasize:cint):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_flags(md:PEVP_MD; flags:culong):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_init(md:PEVP_MD; init:TEVP_MD_init_cb):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_update(md:PEVP_MD; update:TEVP_MD_update_cb):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_final(md:PEVP_MD; final:TEVP_MD_final_cb):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_copy(md:PEVP_MD; copy:TEVP_MD_copy_cb):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_cleanup(md:PEVP_MD; cleanup:TEVP_MD_init_cb):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_set_ctrl(md:PEVP_MD; ctrl:TEVP_MD_ctrl_cb):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_input_blocksize(md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_result_size(md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_app_datasize(md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_flags(md:PEVP_MD):culong;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_init(md:PEVP_MD):TEVP_MD_init_cb;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_update(md:PEVP_MD):TEVP_MD_update_cb;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_final(md:PEVP_MD):TEVP_MD_final_cb;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_copy(md:PEVP_MD):TEVP_MD_copy_cb;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_cleanup(md:PEVP_MD):TEVP_MD_init_cb;cdecl; external DLLUtilName;
function  EVP_MD_meth_get_ctrl(md:PEVP_MD):TEVP_MD_ctrl_cb;cdecl; external DLLUtilName;

    const
      EVP_MD_FLAG_ONESHOT = $0001;      
      EVP_MD_FLAG_DIGALGID_MASK = $0018;      
      EVP_MD_FLAG_DIGALGID_NULL = $0000;      
      EVP_MD_FLAG_DIGALGID_ABSENT = $0008;      
      EVP_MD_FLAG_DIGALGID_CUSTOM = $0018;      
      EVP_MD_FLAG_FIPS = $0400;      
      EVP_MD_CTRL_DIGALGID = $1;      
      EVP_MD_CTRL_MICALG = $2;      
      EVP_MD_CTRL_ALG_CTRL = $1000;      
      EVP_MD_CTX_FLAG_ONESHOT = $0001;      
      EVP_MD_CTX_FLAG_CLEANED = $0002;      
      EVP_MD_CTX_FLAG_REUSE = $0004;      
      EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = $0008;      
      EVP_MD_CTX_FLAG_PAD_MASK = $F0;      
      EVP_MD_CTX_FLAG_PAD_PKCS1 = $00;      
      EVP_MD_CTX_FLAG_PAD_X931 = $10;      
      EVP_MD_CTX_FLAG_PAD_PSS = $20;      
      EVP_MD_CTX_FLAG_NO_INIT = $0100;      
      EVP_MD_CTX_FLAG_FINALISE = $0200;      

type
 TEVP_CIPHER_init_cb=function  (ctx:PEVP_CIPHER_CTX; key:pbyte; iv:pbyte; enc:cint):cint;cdecl;
 TEVP_CIPHER_do_cipher_cb=function  (ctx:PEVP_CIPHER_CTX;_out:pbyte;_in:pbyte; inl:size_t):cint;cdecl;
 TEVP_CIPHER_cleanup_cb=function  (para1:PEVP_CIPHER_CTX):cint;cdecl;
 TEVP_CIPHER_asn1_parameters_cb=function  (para1:PEVP_CIPHER_CTX; para2:PASN1_TYPE):cint;cdecl;
 TEVP_CIPHER_ctrl_cb=function  (para1:PEVP_CIPHER_CTX; _type:cint; arg:cint; ptr:pointer):cint;cdecl;

function  EVP_CIPHER_meth_new(cipher_type:cint; block_size:cint; key_len:cint):PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_dup(cipher:PEVP_CIPHER):PEVP_CIPHER;cdecl; external DLLUtilName;
procedure EVP_CIPHER_meth_free(cipher:PEVP_CIPHER);cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_iv_length(cipher:PEVP_CIPHER; iv_len:cint):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_flags(cipher:PEVP_CIPHER; flags:culong):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_impl_ctx_size(cipher:PEVP_CIPHER; ctx_size:cint):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_init(cipher:PEVP_CIPHER; init:TEVP_CIPHER_init_cb):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_do_cipher(cipher:PEVP_CIPHER; do_cipher:TEVP_CIPHER_do_cipher_cb):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_cleanup(cipher:PEVP_CIPHER; cleanup:TEVP_CIPHER_cleanup_cb):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_set_asn1_params(cipher:PEVP_CIPHER; set_asn1_parameters:TEVP_CIPHER_asn1_parameters_cb):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_get_asn1_params(cipher:PEVP_CIPHER; get_asn1_parameters:TEVP_CIPHER_asn1_parameters_cb):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_set_ctrl(cipher:PEVP_CIPHER; ctrl:TEVP_CIPHER_ctrl_cb):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_get_init(cipher:PEVP_CIPHER):TEVP_CIPHER_init_cb;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_get_do_cipher(cipher:PEVP_CIPHER):TEVP_CIPHER_do_cipher_cb;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_get_cleanup(cipher:PEVP_CIPHER):TEVP_CIPHER_cleanup_cb;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_get_set_asn1_params(cipher:PEVP_CIPHER):TEVP_CIPHER_asn1_parameters_cb;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_get_get_asn1_params(cipher:PEVP_CIPHER):TEVP_CIPHER_asn1_parameters_cb;cdecl; external DLLUtilName;
function  EVP_CIPHER_meth_get_ctrl(cipher:PEVP_CIPHER):TEVP_CIPHER_ctrl_cb;cdecl; external DLLUtilName;

    const
      EVP_CIPH_STREAM_CIPHER = $0;      
      EVP_CIPH_ECB_MODE = $1;      
      EVP_CIPH_CBC_MODE = $2;      
      EVP_CIPH_CFB_MODE = $3;      
      EVP_CIPH_OFB_MODE = $4;      
      EVP_CIPH_CTR_MODE = $5;      
      EVP_CIPH_GCM_MODE = $6;      
      EVP_CIPH_CCM_MODE = $7;      
      EVP_CIPH_XTS_MODE = $10001;      
      EVP_CIPH_WRAP_MODE = $10002;      
      EVP_CIPH_OCB_MODE = $10003;      
      EVP_CIPH_MODE = $F0007;      
      EVP_CIPH_VARIABLE_LENGTH = $8;      
      EVP_CIPH_CUSTOM_IV = $10;      
      EVP_CIPH_ALWAYS_CALL_INIT = $20;      
      EVP_CIPH_CTRL_INIT = $40;      
      EVP_CIPH_CUSTOM_KEY_LENGTH = $80;      
      EVP_CIPH_NO_PADDING = $100;      
      EVP_CIPH_RAND_KEY = $200;      
      EVP_CIPH_CUSTOM_COPY = $400;      
      EVP_CIPH_FLAG_DEFAULT_ASN1 = $1000;      
      EVP_CIPH_FLAG_LENGTH_BITS = $2000;      
      EVP_CIPH_FLAG_FIPS = $4000;      
      EVP_CIPH_FLAG_NON_FIPS_ALLOW = $8000;      
      EVP_CIPH_FLAG_CUSTOM_CIPHER = $100000;      
      EVP_CIPH_FLAG_AEAD_CIPHER = $200000;      
      EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK = $400000;      
      EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = $1;      
      EVP_CTRL_INIT = $0;      
      EVP_CTRL_SET_KEY_LENGTH = $1;      
      EVP_CTRL_GET_RC2_KEY_BITS = $2;      
      EVP_CTRL_SET_RC2_KEY_BITS = $3;      
      EVP_CTRL_GET_RC5_ROUNDS = $4;      
      EVP_CTRL_SET_RC5_ROUNDS = $5;      
      EVP_CTRL_RAND_KEY = $6;      
      EVP_CTRL_PBE_PRF_NID = $7;      
      EVP_CTRL_COPY = $8;      
      EVP_CTRL_AEAD_SET_IVLEN = $9;      
      EVP_CTRL_AEAD_GET_TAG = $10;      
      EVP_CTRL_AEAD_SET_TAG = $11;      
      EVP_CTRL_AEAD_SET_IV_FIXED = $12;      
      EVP_CTRL_GCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;      
      EVP_CTRL_GCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;      
      EVP_CTRL_GCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;      
      EVP_CTRL_GCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;      
      EVP_CTRL_GCM_IV_GEN = $13;      
      EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;      
      EVP_CTRL_CCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;      
      EVP_CTRL_CCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;      
      EVP_CTRL_CCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;      
      EVP_CTRL_CCM_SET_L = $14;      
      EVP_CTRL_CCM_SET_MSGLEN = $15;      
      EVP_CTRL_AEAD_TLS1_AAD = $16;      
      EVP_CTRL_AEAD_SET_MAC_KEY = $17;      
      EVP_CTRL_GCM_SET_IV_INV = $18;      
      EVP_CTRL_TLS1_1_MULTIBLOCK_AAD = $19;      
      EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT = $1a;      
      EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT = $1b;      
      EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE = $1c;      
      EVP_CTRL_SSL3_MASTER_SECRET = $1d;      
      EVP_CTRL_SET_SBOX = $1e;      
      EVP_CTRL_SBOX_USED = $1f;      
      EVP_CTRL_KEY_MESH = $20;      
      EVP_CTRL_BLOCK_PADDING_MODE = $21;      
      EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS = $22;      
      EVP_CTRL_SET_PIPELINE_INPUT_BUFS = $23;      
      EVP_CTRL_SET_PIPELINE_INPUT_LENS = $24;      
      EVP_PADDING_PKCS7 = 1;      
      EVP_PADDING_ISO7816_4 = 2;      
      EVP_PADDING_ANSI923 = 3;      
      EVP_PADDING_ISO10126 = 4;      
      EVP_PADDING_ZERO = 5;      
      EVP_AEAD_TLS1_AAD_LEN = 13;

    type
      PEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = ^TEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;
      TEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = record
          _out : pbyte;
          inp : pbyte;
          len : size_t;
          interleave : cuint;
        end;

    const
      EVP_GCM_TLS_FIXED_IV_LEN = 4;      
      EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;      
      EVP_GCM_TLS_TAG_LEN = 16;      
      EVP_CCM_TLS_FIXED_IV_LEN = 4;      
      EVP_CCM_TLS_EXPLICIT_IV_LEN = 8;      
    type
      Pevp_cipher_info= ^Tevp_cipher_info_st;
      Tevp_cipher_info_st = record
          cipher : PEVP_CIPHER;
          iv : array[0..15] of byte;
        end;
      TEVP_CIPHER_INFO = Tevp_cipher_info_st;

    function  EVP_PKEY_assign_RSA(pkey:PEVP_PKEY;rsa : Pointer) : cint;

    function  EVP_PKEY_assign_DSA(pkey:PEVP_PKEY;dsa : Pointer) : cint;

    function  EVP_PKEY_assign_DH(pkey:PEVP_PKEY;dh : Pointer) : cint;

    function  EVP_PKEY_assign_EC_KEY(pkey:PEVP_PKEY;eckey : Pointer) : cint;

    function  EVP_get_digestbynid(a : cint) : PEVP_MD;

    function  EVP_get_digestbyobj(a : PASN1_OBJECT) : PEVP_MD;

    function  EVP_get_cipherbynid(a : cint) : PEVP_CIPHER;

    function  EVP_get_cipherbyobj(a : PASN1_OBJECT) : PEVP_CIPHER;

function  EVP_MD_type(md:PEVP_MD):cint;cdecl; external DLLUtilName;

    function  EVP_MD_nid(e : PEVP_MD) : cint;

    function  EVP_MD_name(e : PEVP_MD) : PByte;

function  EVP_MD_pkey_type(md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_MD_size(md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_MD_block_size(md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_MD_flags(md:PEVP_MD):culong;cdecl; external DLLUtilName;
function  EVP_MD_CTX_md(ctx:PEVP_MD_CTX):PEVP_MD;cdecl; external DLLUtilName;
function  EVP_MD_CTX_update_fn(ctx:PEVP_MD_CTX):TEVP_MD_update_cb;cdecl; external DLLUtilName;
procedure EVP_MD_CTX_set_update_fn(ctx:PEVP_MD_CTX; update:TEVP_MD_update_cb);cdecl; external DLLUtilName;

    function  EVP_MD_CTX_size(e : PEVP_MD_CTX) : cint;

    function  EVP_MD_CTX_block_size(e : PEVP_MD_CTX) : cint;

    function  EVP_MD_CTX_type(e : PEVP_MD_CTX) : cint;

function  EVP_MD_CTX_pkey_ctx(ctx:PEVP_MD_CTX):PEVP_PKEY_CTX;cdecl; external DLLUtilName;
function  EVP_MD_CTX_md_data(ctx:PEVP_MD_CTX):pointer;cdecl; external DLLUtilName;
function  EVP_CIPHER_nid(cipher:PEVP_CIPHER):cint;cdecl; external DLLUtilName;

    function  EVP_CIPHER_name(e : PEVP_CIPHER) : PByte;

function  EVP_CIPHER_block_size(cipher:PEVP_CIPHER):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_impl_ctx_size(cipher:PEVP_CIPHER):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_key_length(cipher:PEVP_CIPHER):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_iv_length(cipher:PEVP_CIPHER):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_flags(cipher:PEVP_CIPHER):culong;cdecl; external DLLUtilName;

    function  EVP_CIPHER_mode(e : PEVP_CIPHER) : Boolean;

function  EVP_CIPHER_CTX_cipher(ctx:PEVP_CIPHER_CTX):PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_encrypting(ctx:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_nid(ctx:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_block_size(ctx:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_key_length(ctx:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_iv_length(ctx:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_iv(ctx:PEVP_CIPHER_CTX):pbyte;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_original_iv(ctx:PEVP_CIPHER_CTX):pbyte;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_iv_noconst(ctx:PEVP_CIPHER_CTX):pbyte;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_buf_noconst(ctx:PEVP_CIPHER_CTX):pbyte;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_num(ctx:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
procedure EVP_CIPHER_CTX_set_num(ctx:PEVP_CIPHER_CTX; num:cint);cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_copy(_out:PEVP_CIPHER_CTX;_in:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_get_app_data(ctx:PEVP_CIPHER_CTX):pointer;cdecl; external DLLUtilName;
procedure EVP_CIPHER_CTX_set_app_data(ctx:PEVP_CIPHER_CTX; data:pointer);cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_get_cipher_data(ctx:PEVP_CIPHER_CTX):pointer;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_set_cipher_data(ctx:PEVP_CIPHER_CTX; cipher_data:pointer):pointer;cdecl; external DLLUtilName;

    function  EVP_CIPHER_CTX_type(c : PEVP_CIPHER_CTX) : cint;

    function  EVP_CIPHER_CTX_flags(c : PEVP_CIPHER_CTX) : culong;

    function  EVP_CIPHER_CTX_mode(c : PEVP_CIPHER_CTX) : Boolean;

    function  EVP_ENCODE_LENGTH(l : longint) : longint;

    function  EVP_DECODE_LENGTH(l : longint) : longint;

    function  EVP_SignInit_ex(a:PEVP_MD_CTX;b:PEVP_MD;c:PENGINE) : cint;

    function  EVP_SignInit(a:PEVP_MD_CTX;b:PEVP_MD) : cint;

    function  EVP_SignUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t) : cint;

    function  EVP_VerifyInit_ex(a:PEVP_MD_CTX;b:PEVP_MD;c:PENGINE) : cint;

    function  EVP_VerifyInit(a:PEVP_MD_CTX;b:PEVP_MD) : cint;

    function  EVP_VerifyUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t) : cint;

    function  EVP_OpenUpdate(a:PEVP_CIPHER_CTX;b:pbyte;c:pcint;d:pbyte;e:cint) : cint;

    function  EVP_SealUpdate(a:PEVP_CIPHER_CTX;b:pbyte;c:pcint;d:pbyte;e:cint) : cint;

    function  EVP_DigestSignUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t):cint;

    function  EVP_DigestVerifyUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t) : cint;

    function  BIO_set_md(b:PBIO;md : Pointer) : clong;

    function  BIO_get_md(b:PBIO;mdp : Pointer) : clong;

    function  BIO_get_md_ctx(b:PBIO;mdcp : Pointer) : clong;

    function  BIO_set_md_ctx(b:PBIO;mdcp : Pointer) : clong;

    function  BIO_get_cipher_status(b : PBIO) : clong;

    function  BIO_get_cipher_ctx(b : PBIO;c_pp : Pointer) : clong;

function  EVP_Cipher(c:PEVP_CIPHER_CTX;_out:pbyte;_in:pbyte; inl:cuint):cint;cdecl; external DLLUtilName;

    function  EVP_add_cipher_alias(n,_alias : PByte) : cint;

    function  EVP_add_digest_alias(n,_alias : PByte) : cint;

function  EVP_MD_CTX_ctrl(ctx:PEVP_MD_CTX; cmd:cint; p1:cint; p2:pointer):cint;cdecl; external DLLUtilName;
function  EVP_MD_CTX_new:PEVP_MD_CTX;cdecl; external DLLUtilName;
function  EVP_MD_CTX_reset(ctx:PEVP_MD_CTX):cint;cdecl; external DLLUtilName;
procedure EVP_MD_CTX_free(ctx:PEVP_MD_CTX);cdecl; external DLLUtilName;

    function  EVP_MD_CTX_create : PEVP_MD_CTX;

    function  EVP_MD_CTX_init(ctx : PEVP_MD_CTX) : cint;

    Procedure EVP_MD_CTX_destroy(ctx : PEVP_MD_CTX);

function  EVP_MD_CTX_copy_ex(_out:PEVP_MD_CTX;_in:PEVP_MD_CTX):cint;cdecl; external DLLUtilName;
procedure EVP_MD_CTX_set_flags(ctx:PEVP_MD_CTX; flags:cint);cdecl; external DLLUtilName;
procedure EVP_MD_CTX_clear_flags(ctx:PEVP_MD_CTX; flags:cint);cdecl; external DLLUtilName;
function  EVP_MD_CTX_test_flags(ctx:PEVP_MD_CTX; flags:cint):cint;cdecl; external DLLUtilName;
function  EVP_DigestInit_ex(ctx:PEVP_MD_CTX; _type:PEVP_MD; impl:PENGINE):cint;cdecl; external DLLUtilName;
function  EVP_DigestUpdate(ctx:PEVP_MD_CTX; d:pointer; cnt:size_t):cint;cdecl; external DLLUtilName;
function  EVP_DigestFinal_ex(ctx:PEVP_MD_CTX; md:pbyte; s:pcuint):cint;cdecl; external DLLUtilName;
function  EVP_Digest(data:pointer; count:size_t; md:pbyte; size:pcuint; _type:PEVP_MD; 
               impl:PENGINE):cint;cdecl; external DLLUtilName;
function  EVP_MD_CTX_copy(_out:PEVP_MD_CTX;_in:PEVP_MD_CTX):cint;cdecl; external DLLUtilName;
function  EVP_DigestInit(ctx:PEVP_MD_CTX; _type:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_DigestFinal(ctx:PEVP_MD_CTX; md:pbyte; s:pcuint):cint;cdecl; external DLLUtilName;
function  EVP_read_pw_string(buf:pbyte; length:cint; prompt:pbyte; verify:cint):cint;cdecl; external DLLUtilName;
function  EVP_read_pw_string_min(buf:pbyte; minlen:cint; maxlen:cint; prompt:pbyte; verify:cint):cint;cdecl; external DLLUtilName;
procedure EVP_set_pw_prompt(prompt:pbyte);cdecl; external DLLUtilName;
function  EVP_get_pw_prompt:pbyte;cdecl; external DLLUtilName;
function  EVP_BytesToKey(_type:PEVP_CIPHER; md:PEVP_MD; salt:pbyte; data:pbyte; datal:cint; 
               count:cint; key:pbyte; iv:pbyte):cint;cdecl; external DLLUtilName;
procedure EVP_CIPHER_CTX_set_flags(ctx:PEVP_CIPHER_CTX; flags:cint);cdecl; external DLLUtilName;
procedure EVP_CIPHER_CTX_clear_flags(ctx:PEVP_CIPHER_CTX; flags:cint);cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_test_flags(ctx:PEVP_CIPHER_CTX; flags:cint):cint;cdecl; external DLLUtilName;
function  EVP_EncryptInit(ctx:PEVP_CIPHER_CTX; cipher:PEVP_CIPHER; key:pbyte; iv:pbyte):cint;cdecl; external DLLUtilName;
function  EVP_EncryptInit_ex(ctx:PEVP_CIPHER_CTX; cipher:PEVP_CIPHER; impl:PENGINE; key:pbyte; iv:pbyte):cint;cdecl; external DLLUtilName;
function  EVP_EncryptUpdate(ctx:PEVP_CIPHER_CTX;_out:pbyte; outl:pcint;_in:pbyte; inl:cint):cint;cdecl; external DLLUtilName;
function  EVP_EncryptFinal_ex(ctx:PEVP_CIPHER_CTX;_out:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_EncryptFinal(ctx:PEVP_CIPHER_CTX;_out:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_DecryptInit(ctx:PEVP_CIPHER_CTX; cipher:PEVP_CIPHER; key:pbyte; iv:pbyte):cint;cdecl; external DLLUtilName;
function  EVP_DecryptInit_ex(ctx:PEVP_CIPHER_CTX; cipher:PEVP_CIPHER; impl:PENGINE; key:pbyte; iv:pbyte):cint;cdecl; external DLLUtilName;
function  EVP_DecryptUpdate(ctx:PEVP_CIPHER_CTX;_out:pbyte; outl:pcint;_in:pbyte; inl:cint):cint;cdecl; external DLLUtilName;
function  EVP_DecryptFinal(ctx:PEVP_CIPHER_CTX; outm:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_DecryptFinal_ex(ctx:PEVP_CIPHER_CTX; outm:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_CipherInit(ctx:PEVP_CIPHER_CTX; cipher:PEVP_CIPHER; key:pbyte; iv:pbyte; enc:cint):cint;cdecl; external DLLUtilName;
function  EVP_CipherInit_ex(ctx:PEVP_CIPHER_CTX; cipher:PEVP_CIPHER; impl:PENGINE; key:pbyte; iv:pbyte; 
               enc:cint):cint;cdecl; external DLLUtilName;
function  EVP_CipherUpdate(ctx:PEVP_CIPHER_CTX;_out:pbyte; outl:pcint;_in:pbyte; inl:cint):cint;cdecl; external DLLUtilName;
function  EVP_CipherFinal(ctx:PEVP_CIPHER_CTX; outm:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_CipherFinal_ex(ctx:PEVP_CIPHER_CTX; outm:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_SignFinal(ctx:PEVP_MD_CTX; md:pbyte; s:pcuint; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_VerifyFinal(ctx:PEVP_MD_CTX; sigbuf:pbyte; siglen:cuint; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_DigestSignInit(ctx:PEVP_MD_CTX; pctx:PPEVP_PKEY_CTX; _type:PEVP_MD; e:PENGINE; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_DigestSignFinal(ctx:PEVP_MD_CTX; sigret:pbyte; siglen:Psize_t):cint;cdecl; external DLLUtilName;
function  EVP_DigestVerifyInit(ctx:PEVP_MD_CTX; pctx:PPEVP_PKEY_CTX; _type:PEVP_MD; e:PENGINE; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_DigestVerifyFinal(ctx:PEVP_MD_CTX; sig:pbyte; siglen:size_t):cint;cdecl; external DLLUtilName;
function  EVP_OpenInit(ctx:PEVP_CIPHER_CTX; _type:PEVP_CIPHER; ek:pbyte; ekl:cint; iv:pbyte; 
               priv:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_OpenFinal(ctx:PEVP_CIPHER_CTX;_out:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_SealInit(ctx:PEVP_CIPHER_CTX; _type:PEVP_CIPHER; ek:Ppbyte; ekl:pcint; iv:pbyte; 
               pubk:PPEVP_PKEY; npubk:cint):cint;cdecl; external DLLUtilName;
function  EVP_SealFinal(ctx:PEVP_CIPHER_CTX;_out:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_ENCODE_CTX_new:PEVP_ENCODE_CTX;cdecl; external DLLUtilName;
procedure EVP_ENCODE_CTX_free(ctx:PEVP_ENCODE_CTX);cdecl; external DLLUtilName;
function  EVP_ENCODE_CTX_copy(dctx:PEVP_ENCODE_CTX; sctx:PEVP_ENCODE_CTX):cint;cdecl; external DLLUtilName;
function  EVP_ENCODE_CTX_num(ctx:PEVP_ENCODE_CTX):cint;cdecl; external DLLUtilName;
procedure EVP_EncodeInit(ctx:PEVP_ENCODE_CTX);cdecl; external DLLUtilName;
function  EVP_EncodeUpdate(ctx:PEVP_ENCODE_CTX;_out:pbyte; outl:pcint;_in:pbyte; inl:cint):cint;cdecl; external DLLUtilName;
procedure EVP_EncodeFinal(ctx:PEVP_ENCODE_CTX;_out:pbyte; outl:pcint);cdecl; external DLLUtilName;
function  EVP_EncodeBlock(t:pbyte; f:pbyte; n:cint):cint;cdecl; external DLLUtilName;
procedure EVP_DecodeInit(ctx:PEVP_ENCODE_CTX);cdecl; external DLLUtilName;
function  EVP_DecodeUpdate(ctx:PEVP_ENCODE_CTX;_out:pbyte; outl:pcint;_in:pbyte; inl:cint):cint;cdecl; external DLLUtilName;
function  EVP_DecodeFinal(ctx:PEVP_ENCODE_CTX;_out:pbyte; outl:pcint):cint;cdecl; external DLLUtilName;
function  EVP_DecodeBlock(t:pbyte; f:pbyte; n:cint):cint;cdecl; external DLLUtilName;

    function  EVP_CIPHER_CTX_init(c : PEVP_CIPHER_CTX) : cint;

    function  EVP_CIPHER_CTX_cleanup(c : PEVP_CIPHER_CTX) : cint;

function  EVP_CIPHER_CTX_new:PEVP_CIPHER_CTX;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_reset(c:PEVP_CIPHER_CTX):cint;cdecl; external DLLUtilName;
procedure EVP_CIPHER_CTX_free(c:PEVP_CIPHER_CTX);cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_set_key_length(x:PEVP_CIPHER_CTX; keylen:cint):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_set_padding(c:PEVP_CIPHER_CTX; pad:cint):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_ctrl(ctx:PEVP_CIPHER_CTX; _type:cint; arg:cint; ptr:pointer):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_CTX_rand_key(ctx:PEVP_CIPHER_CTX; key:pbyte):cint;cdecl; external DLLUtilName;
function  BIO_f_md:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_f_base64:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_f_cipher:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_f_reliable:PBIO_METHOD;cdecl; external DLLUtilName;
function  BIO_set_cipher(b:PBIO; c:PEVP_CIPHER; k:pbyte; i:pbyte; enc:cint):cint;cdecl; external DLLUtilName;
function  EVP_md_null:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_md2:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_md4:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_md5:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_md5_sha1:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_blake2b512:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_blake2s256:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_sha1:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_sha224:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_sha256:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_sha384:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_sha512:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_mdc2:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_ripemd160:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_whirlpool:PEVP_MD;cdecl; external DLLUtilName;
function  EVP_enc_null:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede3:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede3_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_des_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_des_ede3_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_des_ede3_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede3_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede3_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede3_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_desx_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_des_ede3_wrap:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc4:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc4_40:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc4_hmac_md5:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_idea_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_idea_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_idea_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_idea_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc2_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc2_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc2_40_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc2_64_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc2_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_rc2_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_bf_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_bf_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_bf_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_bf_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_cast5_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_cast5_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_cast5_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_cast5_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc5_32_12_16_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc5_32_12_16_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_rc5_32_12_16_cfb64:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_rc5_32_12_16_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_cfb128:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_aes_128_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_ctr:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_ccm:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_gcm:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_xts:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_wrap:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_wrap_pad:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_ocb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_cfb128:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_aes_192_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_ctr:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_ccm:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_gcm:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_wrap:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_wrap_pad:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_192_ocb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_cfb128:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_aes_256_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_ctr:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_ccm:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_gcm:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_xts:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_wrap:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_wrap_pad:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_ocb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_cbc_hmac_sha1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_cbc_hmac_sha1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_128_cbc_hmac_sha256:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_aes_256_cbc_hmac_sha256:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_128_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_128_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_128_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_128_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_128_cfb128:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_camellia_128_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_128_ctr:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_192_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_192_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_192_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_192_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_192_cfb128:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_camellia_192_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_192_ctr:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_256_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_256_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_256_cfb1:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_256_cfb8:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_256_cfb128:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_camellia_256_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_camellia_256_ctr:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_chacha20:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_chacha20_poly1305:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_seed_ecb:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_seed_cbc:PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_seed_cfb128:PEVP_CIPHER;cdecl; external DLLUtilName;

function  EVP_seed_ofb:PEVP_CIPHER;cdecl; external DLLUtilName;

    function  OPENSSL_add_all_algorithms_conf : cint;

    function  OPENSSL_add_all_algorithms_noconf : cint;

    function  OpenSSL_add_all_algorithms : cint;

    function  OpenSSL_add_all_ciphers : cint;

    function  OpenSSL_add_all_digests : cint;

type
 TEVP_CIPHER_do_all_cb=procedure (ciph:PEVP_CIPHER; from:pbyte; _to:pbyte; x:pointer); cdecl;
 TEVP_CIPHER_do_all_sorted_cb=procedure (ciph:PEVP_CIPHER; from:pbyte; _to:pbyte; x:pointer); cdecl;
 TEVP_MD_do_all_cb=procedure (ciph:PEVP_MD; from:pbyte; _to:pbyte; x:pointer); cdecl;

function  EVP_add_cipher(cipher:PEVP_CIPHER):cint;cdecl; external DLLUtilName;
function  EVP_add_digest(digest:PEVP_MD):cint;cdecl; external DLLUtilName;
function  EVP_get_cipherbyname(name:pbyte):PEVP_CIPHER;cdecl; external DLLUtilName;
function  EVP_get_digestbyname(name:pbyte):PEVP_MD;cdecl; external DLLUtilName;
procedure EVP_CIPHER_do_all(fn:TEVP_CIPHER_do_all_cb; arg:pointer);cdecl; external DLLUtilName;
procedure EVP_CIPHER_do_all_sorted(fn:TEVP_CIPHER_do_all_sorted_cb; arg:pointer);cdecl; external DLLUtilName;
procedure EVP_MD_do_all(fn:TEVP_MD_do_all_cb; arg:pointer);cdecl; external DLLUtilName;
procedure EVP_MD_do_all_sorted(fn:TEVP_MD_do_all_cb; arg:pointer);cdecl; external DLLUtilName;
function  EVP_PKEY_decrypt_old(dec_key:pbyte; enc_key:pbyte; enc_key_len:cint; private_key:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_encrypt_old(enc_key:pbyte; key:pbyte; key_len:cint; pub_key:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_type(_type:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_id(pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_base_id(pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_bits(pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_security_bits(pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_size(pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_set_type(pkey:PEVP_PKEY; _type:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_set_type_str(pkey:PEVP_PKEY; str:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_set1_engine(pkey:PEVP_PKEY; e:PENGINE):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_assign(pkey:PEVP_PKEY; _type:cint; key:pointer):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_get0(pkey:PEVP_PKEY):pointer;cdecl; external DLLUtilName;
function  EVP_PKEY_get0_hmac(pkey:PEVP_PKEY; len:Psize_t):pbyte;cdecl; external DLLUtilName;

    type
      Prsa = ^Trsa_st;
      PPRSA=^PRSA;
      Trsa_st = record
          {undefined structure}
        end;

function  EVP_PKEY_set1_RSA(pkey:PEVP_PKEY; key:Prsa):cint;cdecl; external DLLUtilName;

    type
      Pdsa = ^Tdsa_st;
      Tdsa_st = record
          {undefined structure}
        end;
      PPDSA=^PDSA;


function  EVP_PKEY_set1_DSA(pkey:PEVP_PKEY; key:Pdsa):cint;cdecl; external DLLUtilName;

    type
      Pdh = ^Tdh_st;
      PPDH=^PDH;
      Tdh_st = record
          {undefined structure}
        end;


function  EVP_PKEY_set1_DH(pkey:PEVP_PKEY; key:Pdh):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_set1_EC_KEY(pkey:PEVP_PKEY; key:Pec_key):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_new:PEVP_PKEY;cdecl; external DLLUtilName;
function  EVP_PKEY_up_ref(pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
procedure EVP_PKEY_free(pkey:PEVP_PKEY);cdecl; external DLLUtilName;
function  d2i_PublicKey(_type:cint; a:PPEVP_PKEY; pp:Ppbyte; length:clong):PEVP_PKEY;cdecl; external DLLUtilName;
function  i2d_PublicKey(a:PEVP_PKEY; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_PrivateKey(_type:cint; a:PPEVP_PKEY; pp:Ppbyte; length:clong):PEVP_PKEY;cdecl; external DLLUtilName;
function  d2i_AutoPrivateKey(a:PPEVP_PKEY; pp:Ppbyte; length:clong):PEVP_PKEY;cdecl; external DLLUtilName;
function  i2d_PrivateKey(a:PEVP_PKEY; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_copy_parameters(_to:PEVP_PKEY; from:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_missing_parameters(pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_save_parameters(pkey:PEVP_PKEY; mode:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_cmp_parameters(a:PEVP_PKEY; b:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_cmp(a:PEVP_PKEY; b:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_print_public(_out:PBIO; pkey:PEVP_PKEY; indent:cint; pctx:PASN1_PCTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_print_private(_out:PBIO; pkey:PEVP_PKEY; indent:cint; pctx:PASN1_PCTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_print_params(_out:PBIO; pkey:PEVP_PKEY; indent:cint; pctx:PASN1_PCTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_get_default_digest_nid(pkey:PEVP_PKEY; pnid:pcint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_set1_tls_encodedpoint(pkey:PEVP_PKEY; pt:pbyte; ptlen:size_t):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_get1_tls_encodedpoint(pkey:PEVP_PKEY; ppt:Ppbyte):size_t;cdecl; external DLLUtilName;
function  EVP_CIPHER_type(ctx:PEVP_CIPHER):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_param_to_asn1(c:PEVP_CIPHER_CTX; _type:PASN1_TYPE):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_asn1_to_param(c:PEVP_CIPHER_CTX; _type:PASN1_TYPE):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_set_asn1_iv(c:PEVP_CIPHER_CTX; _type:PASN1_TYPE):cint;cdecl; external DLLUtilName;
function  EVP_CIPHER_get_asn1_iv(c:PEVP_CIPHER_CTX; _type:PASN1_TYPE):cint;cdecl; external DLLUtilName;
function  PKCS5_PBE_keyivgen(ctx:PEVP_CIPHER_CTX; pass:pbyte; passlen:cint; param:PASN1_TYPE; cipher:PEVP_CIPHER; 
               md:PEVP_MD; en_de:cint):cint;cdecl; external DLLUtilName;
function  PKCS5_PBKDF2_HMAC_SHA1(pass:pbyte; passlen:cint; salt:pbyte; saltlen:cint; iter:cint; 
               keylen:cint;_out:pbyte):cint;cdecl; external DLLUtilName;
function  PKCS5_PBKDF2_HMAC(pass:pbyte; passlen:cint; salt:pbyte; saltlen:cint; iter:cint; 
               digest:PEVP_MD; keylen:cint;_out:pbyte):cint;cdecl; external DLLUtilName;
function  PKCS5_v2_PBE_keyivgen(ctx:PEVP_CIPHER_CTX; pass:pbyte; passlen:cint; param:PASN1_TYPE; cipher:PEVP_CIPHER; 
               md:PEVP_MD; en_de:cint):cint;cdecl; external DLLUtilName;
function  EVP_PBE_scrypt(pass:pbyte; passlen:size_t; salt:pbyte; saltlen:size_t; N:uint64; 
               r:uint64; p:uint64; maxmem:uint64; key:pbyte; keylen:size_t):cint;cdecl; external DLLUtilName;
function  PKCS5_v2_scrypt_keyivgen(ctx:PEVP_CIPHER_CTX; pass:pbyte; passlen:cint; param:PASN1_TYPE; c:PEVP_CIPHER; 
               md:PEVP_MD; en_de:cint):cint;cdecl; external DLLUtilName;
procedure PKCS5_PBE_add;cdecl; external DLLUtilName;
function  EVP_PBE_CipherInit(pbe_obj:PASN1_OBJECT; pass:pbyte; passlen:cint; param:PASN1_TYPE; ctx:PEVP_CIPHER_CTX; 
               en_de:cint):cint;cdecl; external DLLUtilName;
    const
      EVP_PBE_TYPE_OUTER = $0;      
      EVP_PBE_TYPE_PRF = $1;      
      EVP_PBE_TYPE_KDF = $2;      

function  EVP_PBE_alg_add_type(pbe_type:cint; pbe_nid:cint; cipher_nid:cint; md_nid:cint; keygen:PEVP_PBE_KEYGEN):cint;cdecl; external DLLUtilName;
function  EVP_PBE_alg_add(nid:cint; cipher:PEVP_CIPHER; md:PEVP_MD; keygen:PEVP_PBE_KEYGEN):cint;cdecl; external DLLUtilName;
function  EVP_PBE_find(_type:cint; pbe_nid:cint; pcnid:pcint; pmnid:pcint; pkeygen:PPEVP_PBE_KEYGEN):cint;cdecl; external DLLUtilName;
procedure EVP_PBE_cleanup;cdecl; external DLLUtilName;
function  EVP_PBE_get(ptype:pcint; ppbe_nid:pcint; num:size_t):cint;cdecl; external DLLUtilName;
    const
      ASN1_PKEY_ALIAS = $1;      
      ASN1_PKEY_DYNAMIC = $2;      
      ASN1_PKEY_SIGPARAM_NULL = $4;      
      ASN1_PKEY_CTRL_PKCS7_SIGN = $1;      
      ASN1_PKEY_CTRL_PKCS7_ENCRYPT = $2;      
      ASN1_PKEY_CTRL_DEFAULT_MD_NID = $3;      
      ASN1_PKEY_CTRL_CMS_SIGN = $5;      
      ASN1_PKEY_CTRL_CMS_ENVELOPE = $7;      
      ASN1_PKEY_CTRL_CMS_RI_TYPE = $8;      
      ASN1_PKEY_CTRL_SET1_TLS_ENCPT = $9;      
      ASN1_PKEY_CTRL_GET1_TLS_ENCPT = $a;      

type
 TEVP_PKEY_pub_decode_cb=function  (pk:PEVP_PKEY; pub:PX509_PUBKEY):cint;cdecl;
 TEVP_PKEY_pub_encode_cb=function  (pub:PX509_PUBKEY; pk:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_pub_cmp_cb=function  (a:PEVP_PKEY; b:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_pub_print_cb=function  (_out:PBIO; pkey:PEVP_PKEY; indent:cint; pctx:PASN1_PCTX):cint;cdecl;
 TEVP_PKEY_pkey_size_cb=function  (pk:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_pkey_bits_cb=function  (pk:PEVP_PKEY):cint;cdecl;

 TEVP_PKEY_priv_decode_cb=function  (pk:PEVP_PKEY; p8inf:PPKCS8_PRIV_KEY_INFO):cint;cdecl;
 TEVP_PKEY_priv_encode_cb=function  (p8:PPKCS8_PRIV_KEY_INFO; pk:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_priv_print_cb=function  (_out:PBIO; pkey:PEVP_PKEY; indent:cint; pctx:PASN1_PCTX):cint;cdecl;

 TEVP_PKEY_param_decode_cb=function  (pkey:PEVP_PKEY; pder:Ppbyte; derlen:cint):cint;cdecl;
 TEVP_PKEY_param_encode_cb=function  (pkey:PEVP_PKEY; pder:Ppbyte):cint;cdecl;
 TEVP_PKEY_param_missing_cb=function  (pk:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_param_copy_cb=function  (_to:PEVP_PKEY; from:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_param_cmp_cb=function  (a:PEVP_PKEY; b:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_param_print_cb=function  (_out:PBIO; pkey:PEVP_PKEY; indent:cint; pctx:PASN1_PCTX):cint;cdecl;

 TEVP_PKEY_pkey_free_cb=procedure (pkey:PEVP_PKEY);cdecl;
 TEVP_PKEY_pkey_ctrl_cb=function  (pkey:PEVP_PKEY; op:cint; arg1:clong; arg2:pointer):cint;cdecl;
 TEVP_PKEY_item_verify_cb=function  (ctx:PEVP_MD_CTX; it:PASN1_ITEM; asn:pointer; a:PX509_ALGOR; sig:PASN1_BIT_STRING;pkey:PEVP_PKEY):cint;cdecl;
 TEVP_PKEY_item_sign_cb=function  (ctx:PEVP_MD_CTX; it:PASN1_ITEM; asn:pointer; alg1:PX509_ALGOR; alg2:PX509_ALGOR;sig:PASN1_BIT_STRING):cint;cdecl;
 TEVP_PKEY_pkey_security_bits_cb=function  (pk:PEVP_PKEY):cint;cdecl;

function  EVP_PKEY_asn1_get_count:cint;cdecl; external DLLUtilName;
function  EVP_PKEY_asn1_get0(idx:cint):PEVP_PKEY_ASN1_METHOD;cdecl; external DLLUtilName;
function  EVP_PKEY_asn1_find(pe:PPENGINE; _type:cint):PEVP_PKEY_ASN1_METHOD;cdecl; external DLLUtilName;
function  EVP_PKEY_asn1_find_str(pe:PPENGINE; str:pbyte; len:cint):PEVP_PKEY_ASN1_METHOD;cdecl; external DLLUtilName;
function  EVP_PKEY_asn1_add0(ameth:PEVP_PKEY_ASN1_METHOD):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_asn1_add_alias(_to:cint; from:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_asn1_get0_info(ppkey_id:pcint; pkey_base_id:pcint; ppkey_flags:pcint; pinfo:Ppbyte; ppem_str:Ppbyte; 
               ameth:PEVP_PKEY_ASN1_METHOD):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_get0_asn1(pkey:PEVP_PKEY):PEVP_PKEY_ASN1_METHOD;cdecl; external DLLUtilName;
function  EVP_PKEY_asn1_new(id:cint; flags:cint; pem_str:pbyte; info:pbyte):PEVP_PKEY_ASN1_METHOD;cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_copy(dst:PEVP_PKEY_ASN1_METHOD; src:PEVP_PKEY_ASN1_METHOD);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_free(ameth:PEVP_PKEY_ASN1_METHOD);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_set_public(ameth:PEVP_PKEY_ASN1_METHOD; pub_decode:TEVP_PKEY_pub_decode_cb; pub_encode:TEVP_PKEY_pub_encode_cb; pub_cmp:TEVP_PKEY_pub_cmp_cb; pub_print:TEVP_PKEY_pub_print_cb;
                pkey_size:TEVP_PKEY_pkey_size_cb; pkey_bits:TEVP_PKEY_pkey_bits_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_set_private(ameth:PEVP_PKEY_ASN1_METHOD; priv_decode:TEVP_PKEY_priv_decode_cb; priv_encode:TEVP_PKEY_priv_encode_cb; priv_print:TEVP_PKEY_priv_print_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_set_param(ameth:PEVP_PKEY_ASN1_METHOD; param_decode:TEVP_PKEY_param_decode_cb; param_encode:TEVP_PKEY_param_encode_cb; param_missing:TEVP_PKEY_param_missing_cb; param_copy:TEVP_PKEY_param_copy_cb;
                param_cmp:TEVP_PKEY_param_cmp_cb; param_print:TEVP_PKEY_param_print_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_set_free(ameth:PEVP_PKEY_ASN1_METHOD; pkey_free:TEVP_PKEY_pkey_free_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_set_ctrl(ameth:PEVP_PKEY_ASN1_METHOD; pkey_ctrl:TEVP_PKEY_pkey_ctrl_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_set_item(ameth:PEVP_PKEY_ASN1_METHOD; item_verify:TEVP_PKEY_item_verify_cb; item_sign:TEVP_PKEY_item_sign_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_asn1_set_security_bits(ameth:PEVP_PKEY_ASN1_METHOD; pkey_security_bits:TEVP_PKEY_pkey_security_bits_cb);cdecl; external DLLUtilName;
    const
      EVP_PKEY_OP_UNDEFINED = 0;      
      EVP_PKEY_OP_PARAMGEN = 1 shl 1;      
      EVP_PKEY_OP_KEYGEN = 1 shl 2;      
      EVP_PKEY_OP_SIGN = 1 shl 3;      
      EVP_PKEY_OP_VERIFY = 1 shl 4;      
      EVP_PKEY_OP_VERIFYRECOVER = 1 shl 5;      
      EVP_PKEY_OP_SIGNCTX = 1 shl 6;      
      EVP_PKEY_OP_VERIFYCTX = 1 shl 7;      
      EVP_PKEY_OP_ENCRYPT = 1 shl 8;      
      EVP_PKEY_OP_DECRYPT = 1 shl 9;      
      EVP_PKEY_OP_DERIVE = 1 shl 10;      
      EVP_PKEY_OP_TYPE_SIG = (((EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY) or EVP_PKEY_OP_VERIFYRECOVER) or EVP_PKEY_OP_SIGNCTX) or EVP_PKEY_OP_VERIFYCTX;      
      EVP_PKEY_OP_TYPE_CRYPT = EVP_PKEY_OP_ENCRYPT or EVP_PKEY_OP_DECRYPT;      
      EVP_PKEY_OP_TYPE_NOGEN = (EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT) or EVP_PKEY_OP_DERIVE;      
      EVP_PKEY_OP_TYPE_GEN = EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN;      

    function  EVP_PKEY_CTX_set_signature_md(ctx:PEVP_PKEY_CTX;md : Pointer) : cint;

    function  EVP_PKEY_CTX_get_signature_md(ctx:PEVP_PKEY_CTX;pmd : Pointer) : cint;

    function  EVP_PKEY_CTX_set_mac_key(ctx:PEVP_PKEY_CTX;key:Pointer;len:cint) : cint;

    const
      EVP_PKEY_CTRL_MD = 1;      
      EVP_PKEY_CTRL_PEER_KEY = 2;      
      EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;      
      EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;      
      EVP_PKEY_CTRL_PKCS7_SIGN = 5;      
      EVP_PKEY_CTRL_SET_MAC_KEY = 6;      
      EVP_PKEY_CTRL_DIGESTINIT = 7;      
      EVP_PKEY_CTRL_SET_IV = 8;      
      EVP_PKEY_CTRL_CMS_ENCRYPT = 9;      
      EVP_PKEY_CTRL_CMS_DECRYPT = 10;      
      EVP_PKEY_CTRL_CMS_SIGN = 11;      
      EVP_PKEY_CTRL_CIPHER = 12;      
      EVP_PKEY_CTRL_GET_MD = 13;      
      EVP_PKEY_ALG_CTRL = $1000;      
      EVP_PKEY_FLAG_AUTOARGLEN = 2;      
      EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;      

function  EVP_PKEY_meth_find(_type:cint):PEVP_PKEY_METHOD;cdecl; external DLLUtilName;
function  EVP_PKEY_meth_new(id:cint; flags:cint):PEVP_PKEY_METHOD;cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get0_info(ppkey_id:pcint; pflags:pcint; meth:PEVP_PKEY_METHOD);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_copy(dst:PEVP_PKEY_METHOD; src:PEVP_PKEY_METHOD);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_free(pmeth:PEVP_PKEY_METHOD);cdecl; external DLLUtilName;
function  EVP_PKEY_meth_add0(pmeth:PEVP_PKEY_METHOD):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_new(pkey:PEVP_PKEY; e:PENGINE):PEVP_PKEY_CTX;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_new_id(id:cint; e:PENGINE):PEVP_PKEY_CTX;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_dup(ctx:PEVP_PKEY_CTX):PEVP_PKEY_CTX;cdecl; external DLLUtilName;
procedure EVP_PKEY_CTX_free(ctx:PEVP_PKEY_CTX);cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_ctrl(ctx:PEVP_PKEY_CTX; keytype:cint; optype:cint; cmd:cint; p1:cint; 
               p2:pointer):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_ctrl_str(ctx:PEVP_PKEY_CTX; _type:pbyte; value:pbyte):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_str2ctrl(ctx:PEVP_PKEY_CTX; cmd:cint; str:pbyte):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_hex2ctrl(ctx:PEVP_PKEY_CTX; cmd:cint; hex:pbyte):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_get_operation(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
procedure EVP_PKEY_CTX_set0_keygen_info(ctx:PEVP_PKEY_CTX; dat:pcint; datlen:cint);cdecl; external DLLUtilName;
function  EVP_PKEY_new_mac_key(_type:cint; e:PENGINE; key:pbyte; keylen:cint):PEVP_PKEY;cdecl; external DLLUtilName;
procedure EVP_PKEY_CTX_set_data(ctx:PEVP_PKEY_CTX; data:pointer);cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_get_data(ctx:PEVP_PKEY_CTX):pointer;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_get0_pkey(ctx:PEVP_PKEY_CTX):PEVP_PKEY;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_get0_peerkey(ctx:PEVP_PKEY_CTX):PEVP_PKEY;cdecl; external DLLUtilName;
procedure EVP_PKEY_CTX_set_app_data(ctx:PEVP_PKEY_CTX; data:pointer);cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_get_app_data(ctx:PEVP_PKEY_CTX):pointer;cdecl; external DLLUtilName;
function  EVP_PKEY_sign_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_sign(ctx:PEVP_PKEY_CTX; sig:pbyte; siglen:Psize_t; tbs:pbyte; tbslen:size_t):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_verify_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_verify(ctx:PEVP_PKEY_CTX; sig:pbyte; siglen:size_t; tbs:pbyte; tbslen:size_t):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_verify_recover_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_verify_recover(ctx:PEVP_PKEY_CTX; rout:pbyte; routlen:Psize_t; sig:pbyte; siglen:size_t):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_encrypt_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_encrypt(ctx:PEVP_PKEY_CTX;_out:pbyte; outlen:Psize_t;_in:pbyte; inlen:size_t):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_decrypt_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_decrypt(ctx:PEVP_PKEY_CTX;_out:pbyte; outlen:Psize_t;_in:pbyte; inlen:size_t):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_derive_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_derive_set_peer(ctx:PEVP_PKEY_CTX; peer:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_derive(ctx:PEVP_PKEY_CTX; key:pbyte; keylen:Psize_t):cint;cdecl; external DLLUtilName;
    type
      PEVP_PKEY_gen_cb = ^TEVP_PKEY_gen_cb;
      TEVP_PKEY_gen_cb = function(ctx:PEVP_PKEY_CTX):cint;cdecl;
      TEVP_PKEY_copy_cb=function  (dst:PEVP_PKEY_CTX; src:PEVP_PKEY_CTX):cint;cdecl;
      TEVP_PKEY_cleanup_cb=procedure (ctx:PEVP_PKEY_CTX);cdecl;
      TEVP_PKEY_keygen_cb=function  (ctx:PEVP_PKEY_CTX; pkey:PEVP_PKEY):cint;cdecl;
      TEVP_PKEY_sign_cb=function  (ctx:PEVP_PKEY_CTX; sig:pbyte; siglen:Psize_t; tbs:pbyte; tbslen:size_t):cint;cdecl;
      TEVP_PKEY_verify_cb=function  (ctx:PEVP_PKEY_CTX; sig:pbyte; siglen:size_t; tbs:pbyte; tbslen:size_t):cint;cdecl;
      TEVP_PKEY_signctx_init_cb=function  (ctx:PEVP_PKEY_CTX; mctx:PEVP_MD_CTX):cint;cdecl;
      TEVP_PKEY_signctx_cb=function  (ctx:PEVP_PKEY_CTX; sig:pbyte; siglen:Psize_t; mctx:PEVP_MD_CTX):cint;cdecl;
      TEVP_PKEY_verifyctx_cb=function  (ctx:PEVP_PKEY_CTX; sig:pbyte; siglen:cint; mctx:PEVP_MD_CTX):cint;cdecl;
      TEVP_PKEY_encrypt_cb=function  (ctx:PEVP_PKEY_CTX;_out:pbyte; outlen:Psize_t;_in:pbyte; inlen:size_t):cint;cdecl;
      TEVP_PKEY_derive_cb=function  (ctx:PEVP_PKEY_CTX; key:pbyte; keylen:Psize_t):cint;cdecl;
      TEVP_PKEY_ctrl_cb=function  (ctx:PEVP_PKEY_CTX; _type:cint; p1:cint; p2:pointer):cint;cdecl;
      TEVP_PKEY_ctrl_str_cb=function  (ctx:PEVP_PKEY_CTX; _type:pbyte; value:pbyte):cint;cdecl;

      PEVP_PKEY_copy_cb=^TEVP_PKEY_copy_cb;
      PEVP_PKEY_cleanup_cb=^TEVP_PKEY_cleanup_cb;
      PEVP_PKEY_keygen_cb=^TEVP_PKEY_keygen_cb;
      PEVP_PKEY_sign_cb=^TEVP_PKEY_sign_cb;
      PEVP_PKEY_verify_cb=^TEVP_PKEY_verify_cb;
      PEVP_PKEY_signctx_init_cb=^TEVP_PKEY_signctx_init_cb;
      PEVP_PKEY_signctx_cb=^TEVP_PKEY_signctx_cb;
      PEVP_PKEY_verifyctx_cb=^TEVP_PKEY_verifyctx_cb;
      PEVP_PKEY_encrypt_cb=^TEVP_PKEY_encrypt_cb;
      PEVP_PKEY_derive_cb=^TEVP_PKEY_derive_cb;
      PEVP_PKEY_ctrl_cb=^TEVP_PKEY_ctrl_cb;
      PEVP_PKEY_ctrl_str_cb=^TEVP_PKEY_ctrl_str_cb;

function  EVP_PKEY_paramgen_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_paramgen(ctx:PEVP_PKEY_CTX; ppkey:PPEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_keygen_init(ctx:PEVP_PKEY_CTX):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_keygen(ctx:PEVP_PKEY_CTX; ppkey:PPEVP_PKEY):cint;cdecl; external DLLUtilName;
procedure EVP_PKEY_CTX_set_cb(ctx:PEVP_PKEY_CTX; cb:PEVP_PKEY_gen_cb);cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_get_cb(ctx:PEVP_PKEY_CTX):PEVP_PKEY_gen_cb;cdecl; external DLLUtilName;
function  EVP_PKEY_CTX_get_keygen_info(ctx:PEVP_PKEY_CTX; idx:cint):cint;cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_init(pmeth:PEVP_PKEY_METHOD; init:TEVP_PKEY_gen_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_copy(pmeth:PEVP_PKEY_METHOD; copy:TEVP_PKEY_copy_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_cleanup(pmeth:PEVP_PKEY_METHOD; cleanup:TEVP_PKEY_cleanup_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_paramgen(pmeth:PEVP_PKEY_METHOD; paramgen_init:TEVP_PKEY_gen_cb; paramgen:TEVP_PKEY_keygen_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_keygen(pmeth:PEVP_PKEY_METHOD; keygen_init:TEVP_PKEY_gen_cb; keygen:TEVP_PKEY_keygen_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_sign(pmeth:PEVP_PKEY_METHOD; sign_init:TEVP_PKEY_gen_cb; sign:TEVP_PKEY_sign_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_verify(pmeth:PEVP_PKEY_METHOD; verify_init:TEVP_PKEY_gen_cb; verify:TEVP_PKEY_verify_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_verify_recover(pmeth:PEVP_PKEY_METHOD; verify_recover_init:TEVP_PKEY_gen_cb; verify_recover:TEVP_PKEY_sign_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_signctx(pmeth:PEVP_PKEY_METHOD; signctx_init:TEVP_PKEY_signctx_init_cb; signctx:TEVP_PKEY_signctx_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_verifyctx(pmeth:PEVP_PKEY_METHOD; verifyctx_init:TEVP_PKEY_signctx_init_cb; verifyctx:TEVP_PKEY_verifyctx_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_encrypt(pmeth:PEVP_PKEY_METHOD; encrypt_init:TEVP_PKEY_gen_cb; encryptfn:TEVP_PKEY_encrypt_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_decrypt(pmeth:PEVP_PKEY_METHOD; decrypt_init:TEVP_PKEY_gen_cb; decrypt:TEVP_PKEY_encrypt_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_derive(pmeth:PEVP_PKEY_METHOD; derive_init:TEVP_PKEY_gen_cb; derive:TEVP_PKEY_derive_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_set_ctrl(pmeth:PEVP_PKEY_METHOD; ctrl:TEVP_PKEY_ctrl_cb; ctrl_str:TEVP_PKEY_ctrl_str_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_init(pmeth:PEVP_PKEY_METHOD; pinit:PEVP_PKEY_gen_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_copy(pmeth:PEVP_PKEY_METHOD; pcopy:PEVP_PKEY_copy_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_cleanup(pmeth:PEVP_PKEY_METHOD; pcleanup:PEVP_PKEY_cleanup_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_paramgen(pmeth:PEVP_PKEY_METHOD; pparamgen_init:PEVP_PKEY_gen_cb; pparamgen:PEVP_PKEY_keygen_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_keygen(pmeth:PEVP_PKEY_METHOD; pkeygen_init:PEVP_PKEY_gen_cb; pkeygen:PEVP_PKEY_keygen_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_sign(pmeth:PEVP_PKEY_METHOD; psign_init:PEVP_PKEY_gen_cb; psign:PEVP_PKEY_sign_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_verify(pmeth:PEVP_PKEY_METHOD; pverify_init:PEVP_PKEY_gen_cb; pverify:PEVP_PKEY_verify_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_verify_recover(pmeth:PEVP_PKEY_METHOD; pverify_recover_init:PEVP_PKEY_gen_cb; pverify_recover:PEVP_PKEY_sign_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_signctx(pmeth:PEVP_PKEY_METHOD; psignctx_init:PEVP_PKEY_signctx_init_cb; psignctx:PEVP_PKEY_signctx_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_verifyctx(pmeth:PEVP_PKEY_METHOD; pverifyctx_init:PEVP_PKEY_signctx_init_cb; pverifyctx:PEVP_PKEY_verifyctx_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_encrypt(pmeth:PEVP_PKEY_METHOD; pencrypt_init:PEVP_PKEY_gen_cb; pencryptfn:PEVP_PKEY_encrypt_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_decrypt(pmeth:PEVP_PKEY_METHOD; pdecrypt_init:PEVP_PKEY_gen_cb; pdecrypt:PEVP_PKEY_encrypt_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_derive(pmeth:PEVP_PKEY_METHOD; pderive_init:PEVP_PKEY_gen_cb; pderive:PEVP_PKEY_derive_cb);cdecl; external DLLUtilName;
procedure EVP_PKEY_meth_get_ctrl(pmeth:PEVP_PKEY_METHOD; pctrl:PEVP_PKEY_ctrl_cb; pctrl_str:PEVP_PKEY_ctrl_str_cb);cdecl; external DLLUtilName;
procedure EVP_add_alg_module;cdecl; external DLLUtilName;
function  ERR_load_EVP_strings:cint;cdecl; external DLLUtilName;
    const
      EVP_F_AESNI_INIT_KEY = 165;      
      EVP_F_AES_INIT_KEY = 133;      
      EVP_F_AES_OCB_CIPHER = 169;      
      EVP_F_AES_T4_INIT_KEY = 178;      
      EVP_F_AES_WRAP_CIPHER = 170;      
      EVP_F_ALG_MODULE_INIT = 177;      
      EVP_F_CAMELLIA_INIT_KEY = 159;      
      EVP_F_CHACHA20_POLY1305_CTRL = 182;      
      EVP_F_CMLL_T4_INIT_KEY = 179;      
      EVP_F_DES_EDE3_WRAP_CIPHER = 171;      
      EVP_F_DO_SIGVER_INIT = 161;      
      EVP_F_EVP_CIPHERINIT_EX = 123;      
      EVP_F_EVP_CIPHER_CTX_COPY = 163;      
      EVP_F_EVP_CIPHER_CTX_CTRL = 124;      
      EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 122;      
      EVP_F_EVP_DECRYPTFINAL_EX = 101;      
      EVP_F_EVP_DECRYPTUPDATE = 166;      
      EVP_F_EVP_DIGESTINIT_EX = 128;      
      EVP_F_EVP_ENCRYPTFINAL_EX = 127;      
      EVP_F_EVP_ENCRYPTUPDATE = 167;      
      EVP_F_EVP_MD_CTX_COPY_EX = 110;      
      EVP_F_EVP_MD_SIZE = 162;      
      EVP_F_EVP_OPENINIT = 102;      
      EVP_F_EVP_PBE_ALG_ADD = 115;      
      EVP_F_EVP_PBE_ALG_ADD_TYPE = 160;      
      EVP_F_EVP_PBE_CIPHERINIT = 116;      
      EVP_F_EVP_PBE_SCRYPT = 181;      
      EVP_F_EVP_PKCS82PKEY = 111;      
      EVP_F_EVP_PKEY2PKCS8 = 113;      
      EVP_F_EVP_PKEY_ASN1_ADD0 = 168;      
      EVP_F_EVP_PKEY_COPY_PARAMETERS = 103;      
      EVP_F_EVP_PKEY_CTX_CTRL = 137;      
      EVP_F_EVP_PKEY_CTX_CTRL_STR = 150;      
      EVP_F_EVP_PKEY_CTX_DUP = 156;      
      EVP_F_EVP_PKEY_DECRYPT = 104;      
      EVP_F_EVP_PKEY_DECRYPT_INIT = 138;      
      EVP_F_EVP_PKEY_DECRYPT_OLD = 151;      
      EVP_F_EVP_PKEY_DERIVE = 153;      
      EVP_F_EVP_PKEY_DERIVE_INIT = 154;      
      EVP_F_EVP_PKEY_DERIVE_SET_PEER = 155;      
      EVP_F_EVP_PKEY_ENCRYPT = 105;      
      EVP_F_EVP_PKEY_ENCRYPT_INIT = 139;      
      EVP_F_EVP_PKEY_ENCRYPT_OLD = 152;      
      EVP_F_EVP_PKEY_GET0_DH = 119;      
      EVP_F_EVP_PKEY_GET0_DSA = 120;      
      EVP_F_EVP_PKEY_GET0_EC_KEY = 131;      
      EVP_F_EVP_PKEY_GET0_HMAC = 183;      
      EVP_F_EVP_PKEY_GET0_RSA = 121;      
      EVP_F_EVP_PKEY_KEYGEN = 146;      
      EVP_F_EVP_PKEY_KEYGEN_INIT = 147;      
      EVP_F_EVP_PKEY_NEW = 106;      
      EVP_F_EVP_PKEY_PARAMGEN = 148;      
      EVP_F_EVP_PKEY_PARAMGEN_INIT = 149;      
      EVP_F_EVP_PKEY_SET1_ENGINE = 187;      
      EVP_F_EVP_PKEY_SIGN = 140;      
      EVP_F_EVP_PKEY_SIGN_INIT = 141;      
      EVP_F_EVP_PKEY_VERIFY = 142;      
      EVP_F_EVP_PKEY_VERIFY_INIT = 143;      
      EVP_F_EVP_PKEY_VERIFY_RECOVER = 144;      
      EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT = 145;      
      EVP_F_EVP_SIGNFINAL = 107;      
      EVP_F_EVP_VERIFYFINAL = 108;      
      EVP_F_INT_CTX_NEW = 157;      
      EVP_F_PKCS5_PBE_KEYIVGEN = 117;      
      EVP_F_PKCS5_V2_PBE_KEYIVGEN = 118;      
      EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN = 164;      
      EVP_F_PKCS5_V2_SCRYPT_KEYIVGEN = 180;      
      EVP_F_PKEY_SET_TYPE = 158;      
      EVP_F_RC2_MAGIC_TO_METH = 109;      
      EVP_F_RC5_CTRL = 125;      
      EVP_R_AES_KEY_SETUP_FAILED = 143;      
      EVP_R_BAD_DECRYPT = 100;      
      EVP_R_BUFFER_TOO_SMALL = 155;      
      EVP_R_CAMELLIA_KEY_SETUP_FAILED = 157;      
      EVP_R_CIPHER_PARAMETER_ERROR = 122;      
      EVP_R_COMMAND_NOT_SUPPORTED = 147;      
      EVP_R_COPY_ERROR = 173;      
      EVP_R_CTRL_NOT_IMPLEMENTED = 132;      
      EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED = 133;      
      EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 138;      
      EVP_R_DECODE_ERROR = 114;      
      EVP_R_DIFFERENT_KEY_TYPES = 101;      
      EVP_R_DIFFERENT_PARAMETERS = 153;      
      EVP_R_ERROR_LOADING_SECTION = 165;      
      EVP_R_ERROR_SETTING_FIPS_MODE = 166;      
      EVP_R_EXPECTING_AN_HMAC_KEY = 174;      
      EVP_R_EXPECTING_AN_RSA_KEY = 127;      
      EVP_R_EXPECTING_A_DH_KEY = 128;      
      EVP_R_EXPECTING_A_DSA_KEY = 129;      
      EVP_R_EXPECTING_A_EC_KEY = 142;      
      EVP_R_FIPS_MODE_NOT_SUPPORTED = 167;      
      EVP_R_ILLEGAL_SCRYPT_PARAMETERS = 171;      
      EVP_R_INITIALIZATION_ERROR = 134;      
      EVP_R_INPUT_NOT_INITIALIZED = 111;      
      EVP_R_INVALID_DIGEST = 152;      
      EVP_R_INVALID_FIPS_MODE = 168;      
      EVP_R_INVALID_KEY = 163;      
      EVP_R_INVALID_KEY_LENGTH = 130;      
      EVP_R_INVALID_OPERATION = 148;      
      EVP_R_KEYGEN_FAILURE = 120;      
      EVP_R_MEMORY_LIMIT_EXCEEDED = 172;      
      EVP_R_MESSAGE_DIGEST_IS_NULL = 159;      
      EVP_R_METHOD_NOT_SUPPORTED = 144;      
      EVP_R_MISSING_PARAMETERS = 103;      
      EVP_R_NO_CIPHER_SET = 131;      
      EVP_R_NO_DEFAULT_DIGEST = 158;      
      EVP_R_NO_DIGEST_SET = 139;      
      EVP_R_NO_KEY_SET = 154;      
      EVP_R_NO_OPERATION_SET = 149;      
      EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 150;      
      EVP_R_OPERATON_NOT_INITIALIZED = 151;      
      EVP_R_PARTIALLY_OVERLAPPING = 162;      
      EVP_R_PKEY_ASN1_METHOD_ALREADY_REGISTERED = 164;      
      EVP_R_PRIVATE_KEY_DECODE_ERROR = 145;      
      EVP_R_PRIVATE_KEY_ENCODE_ERROR = 146;      
      EVP_R_PUBLIC_KEY_NOT_RSA = 106;      
      EVP_R_UNKNOWN_CIPHER = 160;      
      EVP_R_UNKNOWN_DIGEST = 161;      
      EVP_R_UNKNOWN_OPTION = 169;      
      EVP_R_UNKNOWN_PBE_ALGORITHM = 121;      
      EVP_R_UNSUPPORTED_ALGORITHM = 156;      
      EVP_R_UNSUPPORTED_CIPHER = 107;      
      EVP_R_UNSUPPORTED_KEYLENGTH = 123;      
      EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION = 124;      
      EVP_R_UNSUPPORTED_KEY_SIZE = 108;      
      EVP_R_UNSUPPORTED_NUMBER_OF_ROUNDS = 135;      
      EVP_R_UNSUPPORTED_PRF = 125;      
      EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM = 118;      
      EVP_R_UNSUPPORTED_SALT_TYPE = 126;      
      EVP_R_WRAP_MODE_NOT_ALLOWED = 170;      
      EVP_R_WRONG_FINAL_BLOCK_LENGTH = 109;      
{$define HEADER_EC_H}    
      OPENSSL_ECC_MAX_FIELD_BITS = 661;      
    type
      Ppoint_conversion_form_t = ^Tpoint_conversion_form_t;
      Tpoint_conversion_form_t =  Longint;
      Const
        POINT_CONVERSION_COMPRESSED = 2;
        POINT_CONVERSION_UNCOMPRESSED = 4;
        POINT_CONVERSION_HYBRID = 6;

    type
      TEC_METHOD=record end;
      PEC_METHOD=^TEC_METHOD;

      TEC_GROUP=record end;
      PEC_GROUP=^TEC_GROUP;
      PPEC_GROUP=^PEC_GROUP;

      TEC_POINT=record end;
      PEC_POINT=^TEC_POINT;
      PPEC_POINT=^PEC_POINT;

      TECPKPARAMETERS=record end;
      PECPKPARAMETERS=^TECPKPARAMETERS;

      TECPARAMETERS=record end;
      PECPARAMETERS=^TECPARAMETERS;

function  EC_GFp_simple_method:PEC_METHOD;cdecl; external DLLUtilName;
function  EC_GFp_mont_method:PEC_METHOD;cdecl; external DLLUtilName;
function  EC_GFp_nist_method:PEC_METHOD;cdecl; external DLLUtilName;
function  EC_GFp_nistp224_method:PEC_METHOD;cdecl; external DLLUtilName;
function  EC_GFp_nistp256_method:PEC_METHOD;cdecl; external DLLUtilName;
function  EC_GFp_nistp521_method:PEC_METHOD;cdecl; external DLLUtilName;
function  EC_GF2m_simple_method:PEC_METHOD;cdecl; external DLLUtilName;
function  EC_GROUP_new(meth:PEC_METHOD):PEC_GROUP;cdecl; external DLLUtilName;
procedure EC_GROUP_free(group:PEC_GROUP);cdecl; external DLLUtilName;
procedure EC_GROUP_clear_free(group:PEC_GROUP);cdecl; external DLLUtilName;
function  EC_GROUP_copy(dst:PEC_GROUP; src:PEC_GROUP):cint;cdecl; external DLLUtilName;
function  EC_GROUP_dup(src:PEC_GROUP):PEC_GROUP;cdecl; external DLLUtilName;
function  EC_GROUP_method_of(group:PEC_GROUP):PEC_METHOD;cdecl; external DLLUtilName;
function  EC_METHOD_get_field_type(meth:PEC_METHOD):cint;cdecl; external DLLUtilName;
function  EC_GROUP_set_generator(group:PEC_GROUP; generator:PEC_POINT; order:PBIGNUM; cofactor:PBIGNUM):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get0_generator(group:PEC_GROUP):PEC_POINT;cdecl; external DLLUtilName;
function  EC_GROUP_get_mont_data(group:PEC_GROUP):PBN_MONT_CTX;cdecl; external DLLUtilName;
function  EC_GROUP_get_order(group:PEC_GROUP; order:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get0_order(group:PEC_GROUP):PBIGNUM;cdecl; external DLLUtilName;
function  EC_GROUP_order_bits(group:PEC_GROUP):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get_cofactor(group:PEC_GROUP; cofactor:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get0_cofactor(group:PEC_GROUP):PBIGNUM;cdecl; external DLLUtilName;
procedure EC_GROUP_set_curve_name(group:PEC_GROUP; nid:cint);cdecl; external DLLUtilName;
function  EC_GROUP_get_curve_name(group:PEC_GROUP):cint;cdecl; external DLLUtilName;
procedure EC_GROUP_set_asn1_flag(group:PEC_GROUP; flag:cint);cdecl; external DLLUtilName;
function  EC_GROUP_get_asn1_flag(group:PEC_GROUP):cint;cdecl; external DLLUtilName;
procedure EC_GROUP_set_point_conversion_form(group:PEC_GROUP; form:Tpoint_conversion_form_t);cdecl; external DLLUtilName;
function  EC_GROUP_get_point_conversion_form(para1:PEC_GROUP):Tpoint_conversion_form_t;cdecl; external DLLUtilName;
function  EC_GROUP_get0_seed(x:PEC_GROUP):pbyte;cdecl; external DLLUtilName;
function  EC_GROUP_get_seed_len(para1:PEC_GROUP):size_t;cdecl; external DLLUtilName;
function  EC_GROUP_set_seed(para1:PEC_GROUP; para2:pbyte; len:size_t):size_t;cdecl; external DLLUtilName;
function  EC_GROUP_set_curve_GFp(group:PEC_GROUP; p:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get_curve_GFp(group:PEC_GROUP; p:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_set_curve_GF2m(group:PEC_GROUP; p:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get_curve_GF2m(group:PEC_GROUP; p:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get_degree(group:PEC_GROUP):cint;cdecl; external DLLUtilName;
function  EC_GROUP_check(group:PEC_GROUP; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_check_discriminant(group:PEC_GROUP; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_cmp(a:PEC_GROUP; b:PEC_GROUP; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_new_curve_GFp(p:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):PEC_GROUP;cdecl; external DLLUtilName;
function  EC_GROUP_new_curve_GF2m(p:PBIGNUM; a:PBIGNUM; b:PBIGNUM; ctx:PBN_CTX):PEC_GROUP;cdecl; external DLLUtilName;
function  EC_GROUP_new_by_curve_name(nid:cint):PEC_GROUP;cdecl; external DLLUtilName;
function  EC_GROUP_new_from_ecparameters(params:PECPARAMETERS):PEC_GROUP;cdecl; external DLLUtilName;
function  EC_GROUP_get_ecparameters(group:PEC_GROUP; params:PECPARAMETERS):PECPARAMETERS;cdecl; external DLLUtilName;
function  EC_GROUP_new_from_ecpkparameters(params:PECPKPARAMETERS):PEC_GROUP;cdecl; external DLLUtilName;
function  EC_GROUP_get_ecpkparameters(group:PEC_GROUP; params:PECPKPARAMETERS):PECPKPARAMETERS;cdecl; external DLLUtilName;
    type
      PEC_builtin_curve = ^TEC_builtin_curve;
      TEC_builtin_curve = record
          nid : cint;
          comment : pbyte;
        end;

function  EC_get_builtin_curves(r:PEC_builtin_curve; nitems:size_t):size_t;cdecl; external DLLUtilName;
function  EC_curve_nid2nist(nid:cint):pbyte;cdecl; external DLLUtilName;
function  EC_curve_nist2nid(name:pbyte):cint;cdecl; external DLLUtilName;
function  EC_POINT_new(group:PEC_GROUP):PEC_POINT;cdecl; external DLLUtilName;
procedure EC_POINT_free(point:PEC_POINT);cdecl; external DLLUtilName;
procedure EC_POINT_clear_free(point:PEC_POINT);cdecl; external DLLUtilName;
function  EC_POINT_copy(dst:PEC_POINT; src:PEC_POINT):cint;cdecl; external DLLUtilName;
function  EC_POINT_dup(src:PEC_POINT; group:PEC_GROUP):PEC_POINT;cdecl; external DLLUtilName;
function  EC_POINT_method_of(point:PEC_POINT):PEC_METHOD;cdecl; external DLLUtilName;
function  EC_POINT_set_to_infinity(group:PEC_GROUP; point:PEC_POINT):cint;cdecl; external DLLUtilName;
function  EC_POINT_set_Jprojective_coordinates_GFp(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y:PBIGNUM; z:PBIGNUM; 
               ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_get_Jprojective_coordinates_GFp(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y:PBIGNUM; z:PBIGNUM; 
               ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_set_affine_coordinates_GFp(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_get_affine_coordinates_GFp(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_set_compressed_coordinates_GFp(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y_bit:cint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_set_affine_coordinates_GF2m(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_get_affine_coordinates_GF2m(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y:PBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_set_compressed_coordinates_GF2m(group:PEC_GROUP; p:PEC_POINT; x:PBIGNUM; y_bit:cint; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_point2oct(group:PEC_GROUP; p:PEC_POINT; form:Tpoint_conversion_form_t; buf:pbyte; len:size_t; 
               ctx:PBN_CTX):size_t;cdecl; external DLLUtilName;
function  EC_POINT_oct2point(group:PEC_GROUP; p:PEC_POINT; buf:pbyte; len:size_t; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_point2buf(group:PEC_GROUP; point:PEC_POINT; form:Tpoint_conversion_form_t; pbuf:Ppbyte; ctx:PBN_CTX):size_t;cdecl; external DLLUtilName;
function  EC_POINT_point2bn(para1:PEC_GROUP; para2:PEC_POINT; form:Tpoint_conversion_form_t; para4:PBIGNUM; para5:PBN_CTX):PBIGNUM;cdecl; external DLLUtilName;
function  EC_POINT_bn2point(para1:PEC_GROUP; para2:PBIGNUM; para3:PEC_POINT; para4:PBN_CTX):PEC_POINT;cdecl; external DLLUtilName;
function  EC_POINT_point2hex(para1:PEC_GROUP; para2:PEC_POINT; form:Tpoint_conversion_form_t; para4:PBN_CTX):pbyte;cdecl; external DLLUtilName;
function  EC_POINT_hex2point(para1:PEC_GROUP; para2:pbyte; para3:PEC_POINT; para4:PBN_CTX):PEC_POINT;cdecl; external DLLUtilName;
function  EC_POINT_add(group:PEC_GROUP; r:PEC_POINT; a:PEC_POINT; b:PEC_POINT; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_dbl(group:PEC_GROUP; r:PEC_POINT; a:PEC_POINT; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_invert(group:PEC_GROUP; a:PEC_POINT; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_is_at_infinity(group:PEC_GROUP; p:PEC_POINT):cint;cdecl; external DLLUtilName;
function  EC_POINT_is_on_curve(group:PEC_GROUP; point:PEC_POINT; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_cmp(group:PEC_GROUP; a:PEC_POINT; b:PEC_POINT; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_make_affine(group:PEC_GROUP; point:PEC_POINT; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINTs_make_affine(group:PEC_GROUP; num:size_t; points:PPEC_POINT; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINTs_mul(group:PEC_GROUP; r:PEC_POINT; n:PBIGNUM; num:size_t; p:PPEC_POINT; 
               m:PPBIGNUM; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_POINT_mul(group:PEC_GROUP; r:PEC_POINT; n:PBIGNUM; q:PEC_POINT; m:PBIGNUM; 
               ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_precompute_mult(group:PEC_GROUP; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_GROUP_have_precompute_mult(group:PEC_GROUP):cint;cdecl; external DLLUtilName;

function  ECPKPARAMETERS_new:PECPKPARAMETERS;cdecl; external DLLUtilName;
procedure ECPKPARAMETERS_free(a:PECPKPARAMETERS);cdecl; external DLLUtilName;

function  ECPARAMETERS_new:PECPARAMETERS;cdecl; external DLLUtilName;
procedure ECPARAMETERS_free(a:PECPARAMETERS);cdecl; external DLLUtilName;
function  EC_GROUP_get_basis_type(para1:PEC_GROUP):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get_trinomial_basis(para1:PEC_GROUP; k:pcuint):cint;cdecl; external DLLUtilName;
function  EC_GROUP_get_pentanomial_basis(para1:PEC_GROUP; k1:pcuint; k2:pcuint; k3:pcuint):cint;cdecl; external DLLUtilName;
    const
      OPENSSL_EC_EXPLICIT_CURVE = $000;      
      OPENSSL_EC_NAMED_CURVE = $001;      

function  d2i_ECPKParameters(para1:PPEC_GROUP;_in:Ppbyte; len:clong):PEC_GROUP;cdecl; external DLLUtilName;
function  i2d_ECPKParameters(para1:PEC_GROUP;_out:Ppbyte):cint;cdecl; external DLLUtilName;

    function  d2i_ECPKParameters_bio(bp:PBIO;x:Ppointer):Pointer;

    function  i2d_ECPKParameters_bio(bp:PBIO;x:pbyte):cint;

function  ECPKParameters_print(bp:PBIO; x:PEC_GROUP; off:cint):cint;cdecl; external DLLUtilName;
//function  ECPKParameters_print_fp(fp:PFILE; x:PEC_GROUP; off:cint):cint;cdecl; external DLLUtilName;
    const
      EC_PKEY_NO_PARAMETERS = $001;      
      EC_PKEY_NO_PUBKEY = $002;      
      EC_FLAG_NON_FIPS_ALLOW = $1;      
      EC_FLAG_FIPS_CHECKED = $2;      
      EC_FLAG_COFACTOR_ECDH = $1000;      

function  EC_KEY_new:PEC_KEY;cdecl; external DLLUtilName;
function  EC_KEY_get_flags(key:PEC_KEY):cint;cdecl; external DLLUtilName;
procedure EC_KEY_set_flags(key:PEC_KEY; flags:cint);cdecl; external DLLUtilName;
procedure EC_KEY_clear_flags(key:PEC_KEY; flags:cint);cdecl; external DLLUtilName;
function  EC_KEY_new_by_curve_name(nid:cint):PEC_KEY;cdecl; external DLLUtilName;
procedure EC_KEY_free(key:PEC_KEY);cdecl; external DLLUtilName;
function  EC_KEY_copy(dst:PEC_KEY; src:PEC_KEY):PEC_KEY;cdecl; external DLLUtilName;
function  EC_KEY_dup(src:PEC_KEY):PEC_KEY;cdecl; external DLLUtilName;
function  EC_KEY_up_ref(key:PEC_KEY):cint;cdecl; external DLLUtilName;
function  EC_KEY_get0_group(key:PEC_KEY):PEC_GROUP;cdecl; external DLLUtilName;
function  EC_KEY_set_group(key:PEC_KEY; group:PEC_GROUP):cint;cdecl; external DLLUtilName;
function  EC_KEY_get0_private_key(key:PEC_KEY):PBIGNUM;cdecl; external DLLUtilName;
function  EC_KEY_set_private_key(key:PEC_KEY; prv:PBIGNUM):cint;cdecl; external DLLUtilName;
function  EC_KEY_get0_public_key(key:PEC_KEY):PEC_POINT;cdecl; external DLLUtilName;
function  EC_KEY_set_public_key(key:PEC_KEY; pub:PEC_POINT):cint;cdecl; external DLLUtilName;
function  EC_KEY_get_enc_flags(key:PEC_KEY):cuint;cdecl; external DLLUtilName;
procedure EC_KEY_set_enc_flags(eckey:PEC_KEY; flags:cuint);cdecl; external DLLUtilName;
function  EC_KEY_get_conv_form(key:PEC_KEY):Tpoint_conversion_form_t;cdecl; external DLLUtilName;
procedure EC_KEY_set_conv_form(eckey:PEC_KEY; cform:Tpoint_conversion_form_t);cdecl; external DLLUtilName;
    function  EC_KEY_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free) : cint;

function  EC_KEY_set_ex_data(key:PEC_KEY; idx:cint; arg:pointer):cint;cdecl; external DLLUtilName;
function  EC_KEY_get_ex_data(key:PEC_KEY; idx:cint):pointer;cdecl; external DLLUtilName;
procedure EC_KEY_set_asn1_flag(eckey:PEC_KEY; asn1_flag:cint);cdecl; external DLLUtilName;
function  EC_KEY_precompute_mult(key:PEC_KEY; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_KEY_generate_key(key:PEC_KEY):cint;cdecl; external DLLUtilName;
function  EC_KEY_check_key(key:PEC_KEY):cint;cdecl; external DLLUtilName;
function  EC_KEY_can_sign(eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  EC_KEY_set_public_key_affine_coordinates(key:PEC_KEY; x:PBIGNUM; y:PBIGNUM):cint;cdecl; external DLLUtilName;
function  EC_KEY_key2buf(key:PEC_KEY; form:Tpoint_conversion_form_t; pbuf:Ppbyte; ctx:PBN_CTX):size_t;cdecl; external DLLUtilName;
function  EC_KEY_oct2key(key:PEC_KEY; buf:pbyte; len:size_t; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
function  EC_KEY_oct2priv(key:PEC_KEY; buf:pbyte; len:size_t):cint;cdecl; external DLLUtilName;
function  EC_KEY_priv2oct(key:PEC_KEY; buf:pbyte; len:size_t):size_t;cdecl; external DLLUtilName;
function  EC_KEY_priv2buf(eckey:PEC_KEY; pbuf:Ppbyte):size_t;cdecl; external DLLUtilName;
function  d2i_ECPrivateKey(key:PPEC_KEY;_in:Ppbyte; len:clong):PEC_KEY;cdecl; external DLLUtilName;
function  i2d_ECPrivateKey(key:PEC_KEY;_out:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_ECParameters(key:PPEC_KEY;_in:Ppbyte; len:clong):PEC_KEY;cdecl; external DLLUtilName;
function  i2d_ECParameters(key:PEC_KEY;_out:Ppbyte):cint;cdecl; external DLLUtilName;
function  o2i_ECPublicKey(key:PPEC_KEY;_in:Ppbyte; len:clong):PEC_KEY;cdecl; external DLLUtilName;
function  i2o_ECPublicKey(key:PEC_KEY;_out:Ppbyte):cint;cdecl; external DLLUtilName;
function  ECParameters_print(bp:PBIO; key:PEC_KEY):cint;cdecl; external DLLUtilName;
function  EC_KEY_print(bp:PBIO; key:PEC_KEY; off:cint):cint;cdecl; external DLLUtilName;
//function  ECParameters_print_fp(fp:PFILE; key:PEC_KEY):cint;cdecl; external DLLUtilName;
//function  EC_KEY_print_fp(fp:PFILE; key:PEC_KEY; off:cint):cint;cdecl; external DLLUtilName;
function  EC_KEY_OpenSSL:PEC_KEY_METHOD;cdecl; external DLLUtilName;
function  EC_KEY_get_default_method:PEC_KEY_METHOD;cdecl; external DLLUtilName;
procedure EC_KEY_set_default_method(meth:PEC_KEY_METHOD);cdecl; external DLLUtilName;
function  EC_KEY_get_method(key:PEC_KEY):PEC_KEY_METHOD;cdecl; external DLLUtilName;
function  EC_KEY_set_method(key:PEC_KEY; meth:PEC_KEY_METHOD):cint;cdecl; external DLLUtilName;
function  EC_KEY_new_method(engine:PENGINE):PEC_KEY;cdecl; external DLLUtilName;
function  ECDH_KDF_X9_62(_out:pbyte; outlen:size_t; Z:pbyte; Zlen:size_t; sinfo:pbyte; 
               sinfolen:size_t; md:PEVP_MD):cint;cdecl; external DLLUtilName;

type
 TECDH_KDF=function  (_in:pointer; inlen:size_t;_out:pointer; outlen:Psize_t):pointer;cdecl;

 TEC_KEY_init_cb=function  (key:PEC_KEY):cint;cdecl;
 TEC_KEY_finish_cb=procedure (key:PEC_KEY);cdecl;
 TEC_KEY_copy_cb=function  (dest:PEC_KEY; src:PEC_KEY):cint;cdecl;
 TEC_KEY_set_group_cb=function  (key:PEC_KEY; grp:PEC_GROUP):cint;cdecl;
 TEC_KEY_set_private_cb=function  (key:PEC_KEY; priv_key:PBIGNUM):cint;cdecl;
 TEC_KEY_set_public_cb=function  (key:PEC_KEY; pub_key:PEC_POINT):cint;cdecl;
 TEC_KEY_ckey_cb=function  (psec:Ppbyte; pseclen:Psize_t; pub_key:PEC_POINT; ecdh:PEC_KEY):cint;cdecl;

 TEC_KEY_sign_cb=function  (_type:cint; dgst:pbyte; dlen:cint; sig:pbyte; siglen:pcuint; kinv:PBIGNUM; r:PBIGNUM; eckey:PEC_KEY):cint;cdecl;
 TEC_KEY_sign_setup_cb=function  (eckey:PEC_KEY; ctx_in:PBN_CTX; kinvp:PPBIGNUM; rp:PPBIGNUM):cint;cdecl;
 TEC_KEY_sign_sig_cb=function  (dgst:pbyte; dgst_len:cint; in_kinv:PBIGNUM; in_r:PBIGNUM; eckey:PEC_KEY):PECDSA_SIG;cdecl;

 TEC_KEY_sign_verify_cb=function  (_type:cint; dgst:pbyte; dgst_len:cint; sigbuf:pbyte; sig_len:cint; eckey:PEC_KEY):cint;cdecl;
 TEC_KEY_sign_verify_sig_cb=function  (dgst:pbyte; dgst_len:cint; sig:PECDSA_SIG; eckey:PEC_KEY):cint;cdecl;

 PEC_KEY_init_cb=^TEC_KEY_init_cb;
 PEC_KEY_finish_cb=^TEC_KEY_finish_cb;
 PEC_KEY_copy_cb=^TEC_KEY_copy_cb;
 PEC_KEY_set_group_cb=^TEC_KEY_set_group_cb;
 PEC_KEY_set_private_cb=^TEC_KEY_set_private_cb;
 PEC_KEY_set_public_cb=^TEC_KEY_set_public_cb;
 PEC_KEY_ckey_cb=^TEC_KEY_ckey_cb;

 PEC_KEY_sign_cb=^TEC_KEY_sign_cb;
 PEC_KEY_sign_setup_cb=^TEC_KEY_sign_setup_cb;
 PEC_KEY_sign_sig_cb=^TEC_KEY_sign_sig_cb;

 PEC_KEY_sign_verify_cb=^TEC_KEY_sign_verify_cb;
 PEC_KEY_sign_verify_sig_cb=^TEC_KEY_sign_verify_sig_cb;


function  ECDH_compute_key(_out:pointer; outlen:size_t; pub_key:PEC_POINT; ecdh:PEC_KEY; KDF:TECDH_KDF):cint;cdecl; external DLLUtilName;

function  ECDSA_SIG_new:PECDSA_SIG;cdecl; external DLLUtilName;
procedure ECDSA_SIG_free(sig:PECDSA_SIG);cdecl; external DLLUtilName;
function  i2d_ECDSA_SIG(sig:PECDSA_SIG; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_ECDSA_SIG(sig:PPECDSA_SIG; pp:Ppbyte; len:clong):PECDSA_SIG;cdecl; external DLLUtilName;
procedure ECDSA_SIG_get0(sig:PECDSA_SIG; pr:PPBIGNUM; ps:PPBIGNUM);cdecl; external DLLUtilName;
function  ECDSA_SIG_set0(sig:PECDSA_SIG; r:PBIGNUM; s:PBIGNUM):cint;cdecl; external DLLUtilName;
function  ECDSA_do_sign(dgst:pbyte; dgst_len:cint; eckey:PEC_KEY):PECDSA_SIG;cdecl; external DLLUtilName;
function  ECDSA_do_sign_ex(dgst:pbyte; dgstlen:cint; kinv:PBIGNUM; rp:PBIGNUM; eckey:PEC_KEY):PECDSA_SIG;cdecl; external DLLUtilName;
function  ECDSA_do_verify(dgst:pbyte; dgst_len:cint; sig:PECDSA_SIG; eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  ECDSA_sign_setup(eckey:PEC_KEY; ctx:PBN_CTX; kinv:PPBIGNUM; rp:PPBIGNUM):cint;cdecl; external DLLUtilName;
function  ECDSA_sign(_type:cint; dgst:pbyte; dgstlen:cint; sig:pbyte; siglen:pcuint; 
               eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  ECDSA_sign_ex(_type:cint; dgst:pbyte; dgstlen:cint; sig:pbyte; siglen:pcuint; 
               kinv:PBIGNUM; rp:PBIGNUM; eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  ECDSA_verify(_type:cint; dgst:pbyte; dgstlen:cint; sig:pbyte; siglen:cint; 
               eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  ECDSA_size(eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  EC_KEY_METHOD_new(meth:PEC_KEY_METHOD):PEC_KEY_METHOD;cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_free(meth:PEC_KEY_METHOD);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_set_init(meth:PEC_KEY_METHOD; init:TEC_KEY_init_cb; finish:TEC_KEY_finish_cb; copy:TEC_KEY_copy_cb; set_group:TEC_KEY_set_group_cb;
                set_private:TEC_KEY_set_private_cb; set_public:TEC_KEY_set_public_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_set_keygen(meth:PEC_KEY_METHOD; keygen:TEC_KEY_init_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_set_compute_key(meth:PEC_KEY_METHOD; ckey:TEC_KEY_ckey_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_set_sign(meth:PEC_KEY_METHOD; sign:TEC_KEY_sign_cb; sign_setup:TEC_KEY_sign_setup_cb;sign_sig:TEC_KEY_sign_sig_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_set_verify(meth:PEC_KEY_METHOD; verify:TEC_KEY_sign_verify_cb; verify_sig:TEC_KEY_sign_verify_sig_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_get_init(meth:PEC_KEY_METHOD; pinit:PEC_KEY_init_cb; pfinish:PEC_KEY_finish_cb; pcopy:PEC_KEY_copy_cb; pset_group:PEC_KEY_set_group_cb;
                pset_private:PEC_KEY_set_private_cb; pset_public:PEC_KEY_set_public_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_get_keygen(meth:PEC_KEY_METHOD; pkeygen:PEC_KEY_init_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_get_compute_key(meth:PEC_KEY_METHOD; pck:PEC_KEY_ckey_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_get_sign(meth:PEC_KEY_METHOD; psign:PEC_KEY_sign_cb; psign_setup:PEC_KEY_sign_setup_cb;psign_sig:PEC_KEY_sign_sig_cb);cdecl; external DLLUtilName;
procedure EC_KEY_METHOD_get_verify(meth:PEC_KEY_METHOD; pverify:PEC_KEY_sign_verify_cb; pverify_sig:PEC_KEY_sign_verify_sig_cb);cdecl; external DLLUtilName;
    function  ECParameters_dup(x : Pointer) : Pointer;

    function  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx:PEVP_PKEY_CTX;nid : cint) : cint;

    function  EVP_PKEY_CTX_set_ec_param_enc(ctx:PEVP_PKEY_CTX;flag : cint) : cint;

    function  EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx:PEVP_PKEY_CTX;flag : cint) : cint;

    function  EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx : PEVP_PKEY_CTX) : cint;

    function  EVP_PKEY_CTX_set_ecdh_kdf_type(ctx : PEVP_PKEY_CTX;kdf : cint) : cint;

    function  EVP_PKEY_CTX_get_ecdh_kdf_type(ctx : PEVP_PKEY_CTX) : cint;

    function  EVP_PKEY_CTX_set_ecdh_kdf_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint;

    function  EVP_PKEY_CTX_get_ecdh_kdf_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint;

    function  EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx : PEVP_PKEY_CTX;len : cint) : cint;

    function  EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx : PEVP_PKEY_CTX;plen : Pointer) : cint;

    function  EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx : PEVP_PKEY_CTX;p:Pointer;plen : cint) : cint;

    function  EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx : PEVP_PKEY_CTX;p : Pointer) : cint;

    const
      EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = EVP_PKEY_ALG_CTRL+1;      
      EVP_PKEY_CTRL_EC_PARAM_ENC = EVP_PKEY_ALG_CTRL+2;      
      EVP_PKEY_CTRL_EC_ECDH_COFACTOR = EVP_PKEY_ALG_CTRL+3;      
      EVP_PKEY_CTRL_EC_KDF_TYPE = EVP_PKEY_ALG_CTRL+4;      
      EVP_PKEY_CTRL_EC_KDF_MD = EVP_PKEY_ALG_CTRL+5;      
      EVP_PKEY_CTRL_GET_EC_KDF_MD = EVP_PKEY_ALG_CTRL+6;      
      EVP_PKEY_CTRL_EC_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+7;      
      EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+8;      
      EVP_PKEY_CTRL_EC_KDF_UKM = EVP_PKEY_ALG_CTRL+9;      
      EVP_PKEY_CTRL_GET_EC_KDF_UKM = EVP_PKEY_ALG_CTRL+10;      
      EVP_PKEY_ECDH_KDF_NONE = 1;      
      EVP_PKEY_ECDH_KDF_X9_62 = 2;      

function  ERR_load_EC_strings:cint;cdecl; external DLLUtilName;

    const
      EC_F_BN_TO_FELEM = 224;      
      EC_F_D2I_ECPARAMETERS = 144;      
      EC_F_D2I_ECPKPARAMETERS = 145;      
      EC_F_D2I_ECPRIVATEKEY = 146;      
      EC_F_DO_EC_KEY_PRINT = 221;      
      EC_F_ECDH_CMS_DECRYPT = 238;      
      EC_F_ECDH_CMS_SET_SHARED_INFO = 239;      
      EC_F_ECDH_COMPUTE_KEY = 246;      
      EC_F_ECDH_SIMPLE_COMPUTE_KEY = 257;      
      EC_F_ECDSA_DO_SIGN_EX = 251;      
      EC_F_ECDSA_DO_VERIFY = 252;      
      EC_F_ECDSA_SIGN_EX = 254;      
      EC_F_ECDSA_SIGN_SETUP = 248;      
      EC_F_ECDSA_SIG_NEW = 265;      
      EC_F_ECDSA_VERIFY = 253;      
      EC_F_ECKEY_PARAM2TYPE = 223;      
      EC_F_ECKEY_PARAM_DECODE = 212;      
      EC_F_ECKEY_PRIV_DECODE = 213;      
      EC_F_ECKEY_PRIV_ENCODE = 214;      
      EC_F_ECKEY_PUB_DECODE = 215;      
      EC_F_ECKEY_PUB_ENCODE = 216;      
      EC_F_ECKEY_TYPE2PARAM = 220;      
      EC_F_ECPARAMETERS_PRINT = 147;      
      EC_F_ECPARAMETERS_PRINT_FP = 148;      
      EC_F_ECPKPARAMETERS_PRINT = 149;      
      EC_F_ECPKPARAMETERS_PRINT_FP = 150;      
      EC_F_ECP_NISTZ256_GET_AFFINE = 240;      
      EC_F_ECP_NISTZ256_MULT_PRECOMPUTE = 243;      
      EC_F_ECP_NISTZ256_POINTS_MUL = 241;      
      EC_F_ECP_NISTZ256_PRE_COMP_NEW = 244;      
      EC_F_ECP_NISTZ256_WINDOWED_MUL = 242;      
      EC_F_ECX_KEY_OP = 266;      
      EC_F_ECX_PRIV_ENCODE = 267;      
      EC_F_ECX_PUB_ENCODE = 268;      
      EC_F_EC_ASN1_GROUP2CURVE = 153;      
      EC_F_EC_ASN1_GROUP2FIELDID = 154;      
      EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY = 208;      
      EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT = 159;      
      EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE = 195;      
      EC_F_EC_GF2M_SIMPLE_OCT2POINT = 160;      
      EC_F_EC_GF2M_SIMPLE_POINT2OCT = 161;      
      EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES = 162;      
      EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES = 163;      
      EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES = 164;      
      EC_F_EC_GFP_MONT_FIELD_DECODE = 133;      
      EC_F_EC_GFP_MONT_FIELD_ENCODE = 134;      
      EC_F_EC_GFP_MONT_FIELD_MUL = 131;      
      EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE = 209;      
      EC_F_EC_GFP_MONT_FIELD_SQR = 132;      
      EC_F_EC_GFP_MONT_GROUP_SET_CURVE = 189;      
      EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE = 225;      
      EC_F_EC_GFP_NISTP224_POINTS_MUL = 228;      
      EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES = 226;      
      EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE = 230;      
      EC_F_EC_GFP_NISTP256_POINTS_MUL = 231;      
      EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES = 232;      
      EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE = 233;      
      EC_F_EC_GFP_NISTP521_POINTS_MUL = 234;      
      EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES = 235;      
      EC_F_EC_GFP_NIST_FIELD_MUL = 200;      
      EC_F_EC_GFP_NIST_FIELD_SQR = 201;      
      EC_F_EC_GFP_NIST_GROUP_SET_CURVE = 202;      
      EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT = 165;      
      EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE = 166;      
      EC_F_EC_GFP_SIMPLE_MAKE_AFFINE = 102;      
      EC_F_EC_GFP_SIMPLE_OCT2POINT = 103;      
      EC_F_EC_GFP_SIMPLE_POINT2OCT = 104;      
      EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE = 137;      
      EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES = 167;      
      EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES = 168;      
      EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES = 169;      
      EC_F_EC_GROUP_CHECK = 170;      
      EC_F_EC_GROUP_CHECK_DISCRIMINANT = 171;      
      EC_F_EC_GROUP_COPY = 106;      
      EC_F_EC_GROUP_GET_CURVE_GF2M = 172;      
      EC_F_EC_GROUP_GET_CURVE_GFP = 130;      
      EC_F_EC_GROUP_GET_DEGREE = 173;      
      EC_F_EC_GROUP_GET_ECPARAMETERS = 261;      
      EC_F_EC_GROUP_GET_ECPKPARAMETERS = 262;      
      EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS = 193;      
      EC_F_EC_GROUP_GET_TRINOMIAL_BASIS = 194;      
      EC_F_EC_GROUP_NEW = 108;      
      EC_F_EC_GROUP_NEW_BY_CURVE_NAME = 174;      
      EC_F_EC_GROUP_NEW_FROM_DATA = 175;      
      EC_F_EC_GROUP_NEW_FROM_ECPARAMETERS = 263;      
      EC_F_EC_GROUP_NEW_FROM_ECPKPARAMETERS = 264;      
      EC_F_EC_GROUP_SET_CURVE_GF2M = 176;      
      EC_F_EC_GROUP_SET_CURVE_GFP = 109;      
      EC_F_EC_GROUP_SET_GENERATOR = 111;      
      EC_F_EC_KEY_CHECK_KEY = 177;      
      EC_F_EC_KEY_COPY = 178;      
      EC_F_EC_KEY_GENERATE_KEY = 179;      
      EC_F_EC_KEY_NEW = 182;      
      EC_F_EC_KEY_NEW_METHOD = 245;      
      EC_F_EC_KEY_OCT2PRIV = 255;      
      EC_F_EC_KEY_PRINT = 180;      
      EC_F_EC_KEY_PRINT_FP = 181;      
      EC_F_EC_KEY_PRIV2OCT = 256;      
      EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES = 229;      
      EC_F_EC_KEY_SIMPLE_CHECK_KEY = 258;      
      EC_F_EC_KEY_SIMPLE_OCT2PRIV = 259;      
      EC_F_EC_KEY_SIMPLE_PRIV2OCT = 260;      
      EC_F_EC_POINTS_MAKE_AFFINE = 136;      
      EC_F_EC_POINT_ADD = 112;      
      EC_F_EC_POINT_CMP = 113;      
      EC_F_EC_POINT_COPY = 114;      
      EC_F_EC_POINT_DBL = 115;      
      EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M = 183;      
      EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP = 116;      
      EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP = 117;      
      EC_F_EC_POINT_INVERT = 210;      
      EC_F_EC_POINT_IS_AT_INFINITY = 118;      
      EC_F_EC_POINT_IS_ON_CURVE = 119;      
      EC_F_EC_POINT_MAKE_AFFINE = 120;      
      EC_F_EC_POINT_NEW = 121;      
      EC_F_EC_POINT_OCT2POINT = 122;      
      EC_F_EC_POINT_POINT2OCT = 123;      
      EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M = 185;      
      EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP = 124;      
      EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M = 186;      
      EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP = 125;      
      EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP = 126;      
      EC_F_EC_POINT_SET_TO_INFINITY = 127;      
      EC_F_EC_PRE_COMP_NEW = 196;      
      EC_F_EC_WNAF_MUL = 187;      
      EC_F_EC_WNAF_PRECOMPUTE_MULT = 188;      
      EC_F_I2D_ECPARAMETERS = 190;      
      EC_F_I2D_ECPKPARAMETERS = 191;      
      EC_F_I2D_ECPRIVATEKEY = 192;      
      EC_F_I2O_ECPUBLICKEY = 151;      
      EC_F_NISTP224_PRE_COMP_NEW = 227;      
      EC_F_NISTP256_PRE_COMP_NEW = 236;      
      EC_F_NISTP521_PRE_COMP_NEW = 237;      
      EC_F_O2I_ECPUBLICKEY = 152;      
      EC_F_OLD_EC_PRIV_DECODE = 222;      
      EC_F_OSSL_ECDH_COMPUTE_KEY = 247;      
      EC_F_OSSL_ECDSA_SIGN_SIG = 249;      
      EC_F_OSSL_ECDSA_VERIFY_SIG = 250;      
      EC_F_PKEY_ECX_DERIVE = 269;      
      EC_F_PKEY_EC_CTRL = 197;      
      EC_F_PKEY_EC_CTRL_STR = 198;      
      EC_F_PKEY_EC_DERIVE = 217;      
      EC_F_PKEY_EC_KEYGEN = 199;      
      EC_F_PKEY_EC_PARAMGEN = 219;      
      EC_F_PKEY_EC_SIGN = 218;      
      EC_R_ASN1_ERROR = 115;      
      EC_R_BAD_SIGNATURE = 156;      
      EC_R_BIGNUM_OUT_OF_RANGE = 144;      
      EC_R_BUFFER_TOO_SMALL = 100;      
      EC_R_COORDINATES_OUT_OF_RANGE = 146;      
      EC_R_CURVE_DOES_NOT_SUPPORT_ECDH = 160;      
      EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING = 159;      
      EC_R_D2I_ECPKPARAMETERS_FAILURE = 117;      
      EC_R_DECODE_ERROR = 142;      
      EC_R_DISCRIMINANT_IS_ZERO = 118;      
      EC_R_EC_GROUP_NEW_BY_NAME_FAILURE = 119;      
      EC_R_FIELD_TOO_LARGE = 143;      
      EC_R_GF2M_NOT_SUPPORTED = 147;      
      EC_R_GROUP2PKPARAMETERS_FAILURE = 120;      
      EC_R_I2D_ECPKPARAMETERS_FAILURE = 121;      
      EC_R_INCOMPATIBLE_OBJECTS = 101;      
      EC_R_INVALID_ARGUMENT = 112;      
      EC_R_INVALID_COMPRESSED_POINT = 110;      
      EC_R_INVALID_COMPRESSION_BIT = 109;      
      EC_R_INVALID_CURVE = 141;      
      EC_R_INVALID_DIGEST = 151;      
      EC_R_INVALID_DIGEST_TYPE = 138;      
      EC_R_INVALID_ENCODING = 102;      
      EC_R_INVALID_FIELD = 103;      
      EC_R_INVALID_FORM = 104;      
      EC_R_INVALID_GROUP_ORDER = 122;      
      EC_R_INVALID_KEY = 116;      
      EC_R_INVALID_OUTPUT_LENGTH = 161;      
      EC_R_INVALID_PEER_KEY = 133;      
      EC_R_INVALID_PENTANOMIAL_BASIS = 132;      
      EC_R_INVALID_PRIVATE_KEY = 123;      
      EC_R_INVALID_TRINOMIAL_BASIS = 137;      
      EC_R_KDF_PARAMETER_ERROR = 148;      
      EC_R_KEYS_NOT_SET = 140;      
      EC_R_MISSING_PARAMETERS = 124;      
      EC_R_MISSING_PRIVATE_KEY = 125;      
      EC_R_NEED_NEW_SETUP_VALUES = 157;      
      EC_R_NOT_A_NIST_PRIME = 135;      
      EC_R_NOT_IMPLEMENTED = 126;      
      EC_R_NOT_INITIALIZED = 111;      
      EC_R_NO_PARAMETERS_SET = 139;      
      EC_R_NO_PRIVATE_VALUE = 154;      
      EC_R_OPERATION_NOT_SUPPORTED = 152;      
      EC_R_PASSED_NULL_PARAMETER = 134;      
      EC_R_PEER_KEY_ERROR = 149;      
      EC_R_PKPARAMETERS2GROUP_FAILURE = 127;      
      EC_R_POINT_ARITHMETIC_FAILURE = 155;      
      EC_R_POINT_AT_INFINITY = 106;      
      EC_R_POINT_IS_NOT_ON_CURVE = 107;      
      EC_R_RANDOM_NUMBER_GENERATION_FAILED = 158;      
      EC_R_SHARED_INFO_ERROR = 150;      
      EC_R_SLOT_FULL = 108;      
      EC_R_UNDEFINED_GENERATOR = 113;      
      EC_R_UNDEFINED_ORDER = 128;      
      EC_R_UNKNOWN_GROUP = 129;      
      EC_R_UNKNOWN_ORDER = 114;      
      EC_R_UNSUPPORTED_FIELD = 131;      
      EC_R_WRONG_CURVE_PARAMETERS = 145;      
      EC_R_WRONG_ORDER = 130;      
{$define HEADER_RSA_H}    
      OPENSSL_RSA_MAX_MODULUS_BITS = 16384;      
      OPENSSL_RSA_FIPS_MIN_MODULUS_BITS = 1024;      
      OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;      
      OPENSSL_RSA_MAX_PUBEXP_BITS = 64;      
      RSA_3 = $3;      
      RSA_F4 = $10001;      
      RSA_METHOD_FLAG_NO_CHECK = $0001;      
      RSA_FLAG_CACHE_PUBLIC = $0002;      
      RSA_FLAG_CACHE_PRIVATE = $0004;      
      RSA_FLAG_BLINDING = $0008;      
      RSA_FLAG_THREAD_SAFE = $0010;      
      RSA_FLAG_EXT_PKEY = $0020;      
      RSA_FLAG_NO_BLINDING = $0080;      
      RSA_FLAG_NO_CONSTTIME = $0000;      
      RSA_FLAG_NO_EXP_CONSTTIME = RSA_FLAG_NO_CONSTTIME;      

    function  EVP_PKEY_CTX_set_rsa_padding(ctx : PEVP_PKEY_CTX;pad : cint) : cint;

    function  EVP_PKEY_CTX_get_rsa_padding(ctx : PEVP_PKEY_CTX;ppad : Pointer) : cint;

    function  EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx : PEVP_PKEY_CTX;len : cint) : cint;

    function  EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx : PEVP_PKEY_CTX;plen : Pointer) : cint;

    function  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx : PEVP_PKEY_CTX;bits : cint) : cint;

    function  EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx : PEVP_PKEY_CTX;pubexp : Pointer) : cint;

    function  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint;

    function  EVP_PKEY_CTX_set_rsa_oaep_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint;

    function  EVP_PKEY_CTX_get_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint;

    function  EVP_PKEY_CTX_get_rsa_oaep_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint;

    function  EVP_PKEY_CTX_set0_rsa_oaep_label(ctx : PEVP_PKEY_CTX;l:Pointer;llen : cint) : cint;

    function  EVP_PKEY_CTX_get0_rsa_oaep_label(ctx : PEVP_PKEY_CTX;l : Pointer) : cint;

    const
      EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL+1;      
      EVP_PKEY_CTRL_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL+2;      
      EVP_PKEY_CTRL_RSA_KEYGEN_BITS = EVP_PKEY_ALG_CTRL+3;      
      EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = EVP_PKEY_ALG_CTRL+4;      
      EVP_PKEY_CTRL_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL+5;      
      EVP_PKEY_CTRL_GET_RSA_PADDING = EVP_PKEY_ALG_CTRL+6;      
      EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL+7;      
      EVP_PKEY_CTRL_GET_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL+8;      
      EVP_PKEY_CTRL_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL+9;      
      EVP_PKEY_CTRL_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL+10;      
      EVP_PKEY_CTRL_GET_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL+11;      
      EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL+12;      
      RSA_PKCS1_PADDING = 1;      
      RSA_SSLV23_PADDING = 2;      
      RSA_NO_PADDING = 3;      
      RSA_PKCS1_OAEP_PADDING = 4;      
      RSA_X931_PADDING = 5;      
      RSA_PKCS1_PSS_PADDING = 6;      
      RSA_PKCS1_PADDING_SIZE = 11;      

    function  RSA_set_app_data(s:PRSA;arg:pointer) : cint;

    function  RSA_get_app_data(s : PRSA) : pointer;

function  RSA_new:PRSA;cdecl; external DLLUtilName;
function  RSA_new_method(engine:PENGINE):PRSA;cdecl; external DLLUtilName;
function  RSA_bits(rsa:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_size(rsa:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_security_bits(rsa:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_set0_key(r:PRSA; n:PBIGNUM; e:PBIGNUM; d:PBIGNUM):cint;cdecl; external DLLUtilName;
function  RSA_set0_factors(r:PRSA; p:PBIGNUM; q:PBIGNUM):cint;cdecl; external DLLUtilName;
function  RSA_set0_crt_params(r:PRSA; dmp1:PBIGNUM; dmq1:PBIGNUM; iqmp:PBIGNUM):cint;cdecl; external DLLUtilName;
procedure RSA_get0_key(r:PRSA; n:PPBIGNUM; e:PPBIGNUM; d:PPBIGNUM);cdecl; external DLLUtilName;
procedure RSA_get0_factors(r:PRSA; p:PPBIGNUM; q:PPBIGNUM);cdecl; external DLLUtilName;
procedure RSA_get0_crt_params(r:PRSA; dmp1:PPBIGNUM; dmq1:PPBIGNUM; iqmp:PPBIGNUM);cdecl; external DLLUtilName;
procedure RSA_clear_flags(r:PRSA; flags:cint);cdecl; external DLLUtilName;
function  RSA_test_flags(r:PRSA; flags:cint):cint;cdecl; external DLLUtilName;
procedure RSA_set_flags(r:PRSA; flags:cint);cdecl; external DLLUtilName;
function  RSA_get0_engine(r:PRSA):PENGINE;cdecl; external DLLUtilName;
function  RSA_X931_derive_ex(rsa:PRSA; p1:PBIGNUM; p2:PBIGNUM; q1:PBIGNUM; q2:PBIGNUM; 
               Xp1:PBIGNUM; Xp2:PBIGNUM; Xp:PBIGNUM; Xq1:PBIGNUM; Xq2:PBIGNUM; 
               Xq:PBIGNUM; e:PBIGNUM; cb:PBN_GENCB):cint;cdecl; external DLLUtilName;
function  RSA_X931_generate_key_ex(rsa:PRSA; bits:cint; e:PBIGNUM; cb:PBN_GENCB):cint;cdecl; external DLLUtilName;
function  RSA_check_key(para1:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_check_key_ex(para1:PRSA; cb:PBN_GENCB):cint;cdecl; external DLLUtilName;
function  RSA_public_encrypt(flen:cint; from:pbyte; _to:pbyte; rsa:PRSA; padding:cint):cint;cdecl; external DLLUtilName;
function  RSA_private_encrypt(flen:cint; from:pbyte; _to:pbyte; rsa:PRSA; padding:cint):cint;cdecl; external DLLUtilName;
function  RSA_public_decrypt(flen:cint; from:pbyte; _to:pbyte; rsa:PRSA; padding:cint):cint;cdecl; external DLLUtilName;
function  RSA_private_decrypt(flen:cint; from:pbyte; _to:pbyte; rsa:PRSA; padding:cint):cint;cdecl; external DLLUtilName;
procedure RSA_free(r:PRSA);cdecl; external DLLUtilName;
function  RSA_up_ref(r:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_flags(r:PRSA):cint;cdecl; external DLLUtilName;
procedure RSA_set_default_method(meth:PRSA_METHOD);cdecl; external DLLUtilName;
function  RSA_get_default_method:PRSA_METHOD;cdecl; external DLLUtilName;
function  RSA_get_method(rsa:PRSA):PRSA_METHOD;cdecl; external DLLUtilName;
function  RSA_set_method(rsa:PRSA; meth:PRSA_METHOD):cint;cdecl; external DLLUtilName;
function  RSA_PKCS1_OpenSSL:PRSA_METHOD;cdecl; external DLLUtilName;
function  RSA_null_method:PRSA_METHOD;cdecl; external DLLUtilName;
function  d2i_RSAPublicKey(a:PPRSA;_in:Ppbyte; len:clong):PRSA;cdecl; external DLLUtilName;
function  i2d_RSAPublicKey(a:PRSA;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  d2i_RSAPrivateKey(a:PPRSA;_in:Ppbyte; len:clong):PRSA;cdecl; external DLLUtilName;
function  i2d_RSAPrivateKey(a:PRSA;_out:Ppbyte):cint;cdecl; external DLLUtilName;

    type
      Prsa_pss_params= ^Trsa_pss_params_st;
      Trsa_pss_params_st = record
          hashAlgorithm : PX509_ALGOR;
          maskGenAlgorithm : PX509_ALGOR;
          saltLength : PASN1_INTEGER;
          trailerField : PASN1_INTEGER;
        end;
      TRSA_PSS_PARAMS = Trsa_pss_params_st;
      PPRSA_PSS_PARAMS=^PRSA_PSS_PARAMS;

function  RSA_PSS_PARAMS_new:PRSA_PSS_PARAMS;cdecl; external DLLUtilName;
procedure RSA_PSS_PARAMS_free(a:PRSA_PSS_PARAMS);cdecl; external DLLUtilName;
function  d2i_RSA_PSS_PARAMS(a:PPRSA_PSS_PARAMS;_in:Ppbyte; len:clong):PRSA_PSS_PARAMS;cdecl; external DLLUtilName;
function  i2d_RSA_PSS_PARAMS(a:PRSA_PSS_PARAMS;_out:Ppbyte):cint;cdecl; external DLLUtilName;

    type
      Prsa_oaep_params= ^Trsa_oaep_params_st;
      Trsa_oaep_params_st = record
          hashFunc : PX509_ALGOR;
          maskGenFunc : PX509_ALGOR;
          pSourceFunc : PX509_ALGOR;
        end;
      TRSA_OAEP_PARAMS = Trsa_oaep_params_st;
      PPRSA_OAEP_PARAMS=^PRSA_OAEP_PARAMS;

function  RSA_OAEP_PARAMS_new:PRSA_OAEP_PARAMS;cdecl; external DLLUtilName;
procedure RSA_OAEP_PARAMS_free(a:PRSA_OAEP_PARAMS);cdecl; external DLLUtilName;
function  d2i_RSA_OAEP_PARAMS(a:PPRSA_OAEP_PARAMS;_in:Ppbyte; len:clong):PRSA_OAEP_PARAMS;cdecl; external DLLUtilName;
function  i2d_RSA_OAEP_PARAMS(a:PRSA_OAEP_PARAMS;_out:Ppbyte):cint;cdecl; external DLLUtilName;

//function  RSA_print_fp(fp:PFILE; r:PRSA; offset:cint):cint;cdecl; external DLLUtilName;
function  RSA_print(bp:PBIO; r:PRSA; offset:cint):cint;cdecl; external DLLUtilName;
function  RSA_sign(_type:cint; m:pbyte; m_length:cuint; sigret:pbyte; siglen:pcuint; 
               rsa:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_verify(_type:cint; m:pbyte; m_length:cuint; sigbuf:pbyte; siglen:cuint; 
               rsa:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_sign_ASN1_OCTET_STRING(_type:cint; m:pbyte; m_length:cuint; sigret:pbyte; siglen:pcuint; 
               rsa:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_verify_ASN1_OCTET_STRING(_type:cint; m:pbyte; m_length:cuint; sigbuf:pbyte; siglen:cuint; 
               rsa:PRSA):cint;cdecl; external DLLUtilName;
function  RSA_blinding_on(rsa:PRSA; ctx:PBN_CTX):cint;cdecl; external DLLUtilName;
procedure RSA_blinding_off(rsa:PRSA);cdecl; external DLLUtilName;
function  RSA_setup_blinding(rsa:PRSA; ctx:PBN_CTX):PBN_BLINDING;cdecl; external DLLUtilName;
function  RSA_padding_add_PKCS1_type_1(_to:pbyte; tlen:cint; f:pbyte; fl:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_check_PKCS1_type_1(_to:pbyte; tlen:cint; f:pbyte; fl:cint; rsa_len:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_PKCS1_type_2(_to:pbyte; tlen:cint; f:pbyte; fl:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_check_PKCS1_type_2(_to:pbyte; tlen:cint; f:pbyte; fl:cint; rsa_len:cint):cint;cdecl; external DLLUtilName;
function  PKCS1_MGF1(mask:pbyte; len:clong; seed:pbyte; seedlen:clong; dgst:PEVP_MD):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_PKCS1_OAEP(_to:pbyte; tlen:cint; f:pbyte; fl:cint; p:pbyte; 
               pl:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_check_PKCS1_OAEP(_to:pbyte; tlen:cint; f:pbyte; fl:cint; rsa_len:cint; 
               p:pbyte; pl:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_PKCS1_OAEP_mgf1(_to:pbyte; tlen:cint; from:pbyte; flen:cint; param:pbyte; 
               plen:cint; md:PEVP_MD; mgf1md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  RSA_padding_check_PKCS1_OAEP_mgf1(_to:pbyte; tlen:cint; from:pbyte; flen:cint; num:cint; 
               param:pbyte; plen:cint; md:PEVP_MD; mgf1md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_SSLv23(_to:pbyte; tlen:cint; f:pbyte; fl:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_check_SSLv23(_to:pbyte; tlen:cint; f:pbyte; fl:cint; rsa_len:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_none(_to:pbyte; tlen:cint; f:pbyte; fl:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_check_none(_to:pbyte; tlen:cint; f:pbyte; fl:cint; rsa_len:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_X931(_to:pbyte; tlen:cint; f:pbyte; fl:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_check_X931(_to:pbyte; tlen:cint; f:pbyte; fl:cint; rsa_len:cint):cint;cdecl; external DLLUtilName;
function  RSA_X931_hash_id(nid:cint):cint;cdecl; external DLLUtilName;
function  RSA_verify_PKCS1_PSS(rsa:PRSA; mHash:pbyte; Hash:PEVP_MD; EM:pbyte; sLen:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_PKCS1_PSS(rsa:PRSA; EM:pbyte; mHash:pbyte; Hash:PEVP_MD; sLen:cint):cint;cdecl; external DLLUtilName;
function  RSA_verify_PKCS1_PSS_mgf1(rsa:PRSA; mHash:pbyte; Hash:PEVP_MD; mgf1Hash:PEVP_MD; EM:pbyte; 
               sLen:cint):cint;cdecl; external DLLUtilName;
function  RSA_padding_add_PKCS1_PSS_mgf1(rsa:PRSA; EM:pbyte; mHash:pbyte; Hash:PEVP_MD; mgf1Hash:PEVP_MD; 
               sLen:cint):cint;cdecl; external DLLUtilName;

    function  RSA_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  RSA_set_ex_data(r:PRSA; idx:cint; arg:pointer):cint;cdecl; external DLLUtilName;
function  RSA_get_ex_data(r:PRSA; idx:cint):pointer;cdecl; external DLLUtilName;
function  RSAPublicKey_dup(rsa:PRSA):PRSA;cdecl; external DLLUtilName;
function  RSAPrivateKey_dup(rsa:PRSA):PRSA;cdecl; external DLLUtilName;

    const
      RSA_FLAG_FIPS_METHOD = $0400;      
      RSA_FLAG_NON_FIPS_ALLOW = $0400;      
      RSA_FLAG_CHECKED = $0800;      

type
 TRSA_pub_enc_cb=function  (flen:cint; from:pbyte; _to:pbyte; rsa:PRSA; padding:cint):cint;cdecl;
 TRSA_mod_exp_cb=function  (r0:PBIGNUM; I:PBIGNUM; rsa:PRSA; ctx:PBN_CTX):cint;cdecl;
 TRSA_bn_mod_exp_cb=function  (r:PBIGNUM; a:PBIGNUM; p:PBIGNUM; m:PBIGNUM; ctx:PBN_CTX; m_ctx:PBN_MONT_CTX):cint;cdecl;
 TRSA_initp_cb=function  (rsa:PRSA):cint;cdecl;
 TRSA_sign_cb=function  (_type:cint; m:pbyte; m_length:cuint; sigret:pbyte; siglen:pcuint;rsa:PRSA):cint;cdecl;
 TRSA_verify_cb=function  (dtype:cint; m:pbyte; m_length:cuint; sigbuf:pbyte; siglen:cuint;rsa:PRSA):cint;cdecl;
 TRSA_keygen_cb=function  (rsa:PRSA; bits:cint; e:PBIGNUM; cb:PBN_GENCB):cint;cdecl;

function  RSA_meth_new(name:pbyte; flags:cint):PRSA_METHOD;cdecl; external DLLUtilName;
procedure RSA_meth_free(meth:PRSA_METHOD);cdecl; external DLLUtilName;
function  RSA_meth_dup(meth:PRSA_METHOD):PRSA_METHOD;cdecl; external DLLUtilName;
function  RSA_meth_get0_name(meth:PRSA_METHOD):pbyte;cdecl; external DLLUtilName;
function  RSA_meth_set1_name(meth:PRSA_METHOD; name:pbyte):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_flags(meth:PRSA_METHOD):cint;cdecl; external DLLUtilName;
function  RSA_meth_set_flags(meth:PRSA_METHOD; flags:cint):cint;cdecl; external DLLUtilName;
function  RSA_meth_get0_app_data(meth:PRSA_METHOD):pointer;cdecl; external DLLUtilName;
function  RSA_meth_set0_app_data(meth:PRSA_METHOD; app_data:pointer):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_pub_enc(meth:PRSA_METHOD):TRSA_pub_enc_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_pub_enc(rsa:PRSA_METHOD; pub_enc:TRSA_pub_enc_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_pub_dec(meth:PRSA_METHOD):TRSA_pub_enc_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_pub_dec(rsa:PRSA_METHOD; pub_dec:TRSA_pub_enc_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_priv_enc(meth:PRSA_METHOD):TRSA_pub_enc_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_priv_enc(rsa:PRSA_METHOD; priv_enc:TRSA_pub_enc_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_priv_dec(meth:PRSA_METHOD):TRSA_pub_enc_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_priv_dec(rsa:PRSA_METHOD; priv_dec:TRSA_pub_enc_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_mod_exp(meth:PRSA_METHOD):TRSA_mod_exp_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_mod_exp(rsa:PRSA_METHOD; mod_exp:TRSA_mod_exp_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_bn_mod_exp(meth:PRSA_METHOD):TRSA_bn_mod_exp_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_bn_mod_exp(rsa:PRSA_METHOD; bn_mod_exp:TRSA_bn_mod_exp_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_init(meth:PRSA_METHOD):TRSA_initp_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_init(rsa:PRSA_METHOD; init:TRSA_initp_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_finish(meth:PRSA_METHOD):TRSA_initp_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_finish(rsa:PRSA_METHOD; finish:TRSA_initp_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_sign(meth:PRSA_METHOD):TRSA_sign_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_sign(rsa:PRSA_METHOD; sign:TRSA_sign_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_verify(meth:PRSA_METHOD):TRSA_verify_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_verify(rsa:PRSA_METHOD; verify:TRSA_verify_cb):cint;cdecl; external DLLUtilName;
function  RSA_meth_get_keygen(meth:PRSA_METHOD):TRSA_keygen_cb;cdecl; external DLLUtilName;
function  RSA_meth_set_keygen(rsa:PRSA_METHOD; keygen:TRSA_keygen_cb):cint;cdecl; external DLLUtilName;
function  ERR_load_RSA_strings:cint;cdecl; external DLLUtilName;

    const
      RSA_F_CHECK_PADDING_MD = 140;      
      RSA_F_ENCODE_PKCS1 = 146;      
      RSA_F_INT_RSA_VERIFY = 145;      
      RSA_F_OLD_RSA_PRIV_DECODE = 147;      
      RSA_F_PKEY_RSA_CTRL = 143;      
      RSA_F_PKEY_RSA_CTRL_STR = 144;      
      RSA_F_PKEY_RSA_SIGN = 142;      
      RSA_F_PKEY_RSA_VERIFY = 149;      
      RSA_F_PKEY_RSA_VERIFYRECOVER = 141;      
      RSA_F_RSA_ALGOR_TO_MD = 156;      
      RSA_F_RSA_BUILTIN_KEYGEN = 129;      
      RSA_F_RSA_CHECK_KEY = 123;      
      RSA_F_RSA_CHECK_KEY_EX = 160;      
      RSA_F_RSA_CMS_DECRYPT = 159;      
      RSA_F_RSA_ITEM_VERIFY = 148;      
      RSA_F_RSA_METH_DUP = 161;      
      RSA_F_RSA_METH_NEW = 162;      
      RSA_F_RSA_METH_SET1_NAME = 163;      
      RSA_F_RSA_MGF1_TO_MD = 157;      
      RSA_F_RSA_NEW_METHOD = 106;      
      RSA_F_RSA_NULL = 124;      
      RSA_F_RSA_NULL_PRIVATE_DECRYPT = 132;      
      RSA_F_RSA_NULL_PRIVATE_ENCRYPT = 133;      
      RSA_F_RSA_NULL_PUBLIC_DECRYPT = 134;      
      RSA_F_RSA_NULL_PUBLIC_ENCRYPT = 135;      
      RSA_F_RSA_OSSL_PRIVATE_DECRYPT = 101;      
      RSA_F_RSA_OSSL_PRIVATE_ENCRYPT = 102;      
      RSA_F_RSA_OSSL_PUBLIC_DECRYPT = 103;      
      RSA_F_RSA_OSSL_PUBLIC_ENCRYPT = 104;      
      RSA_F_RSA_PADDING_ADD_NONE = 107;      
      RSA_F_RSA_PADDING_ADD_PKCS1_OAEP = 121;      
      RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1 = 154;      
      RSA_F_RSA_PADDING_ADD_PKCS1_PSS = 125;      
      RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1 = 152;      
      RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 = 108;      
      RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 = 109;      
      RSA_F_RSA_PADDING_ADD_SSLV23 = 110;      
      RSA_F_RSA_PADDING_ADD_X931 = 127;      
      RSA_F_RSA_PADDING_CHECK_NONE = 111;      
      RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP = 122;      
      RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 = 153;      
      RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 = 112;      
      RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 = 113;      
      RSA_F_RSA_PADDING_CHECK_SSLV23 = 114;      
      RSA_F_RSA_PADDING_CHECK_X931 = 128;      
      RSA_F_RSA_PRINT = 115;      
      RSA_F_RSA_PRINT_FP = 116;      
      RSA_F_RSA_PRIV_ENCODE = 138;      
      RSA_F_RSA_PSS_TO_CTX = 155;      
      RSA_F_RSA_PUB_DECODE = 139;      
      RSA_F_RSA_SETUP_BLINDING = 136;      
      RSA_F_RSA_SIGN = 117;      
      RSA_F_RSA_SIGN_ASN1_OCTET_STRING = 118;      
      RSA_F_RSA_VERIFY = 119;      
      RSA_F_RSA_VERIFY_ASN1_OCTET_STRING = 120;      
      RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1 = 126;      
      RSA_R_ALGORITHM_MISMATCH = 100;      
      RSA_R_BAD_E_VALUE = 101;      
      RSA_R_BAD_FIXED_HEADER_DECRYPT = 102;      
      RSA_R_BAD_PAD_BYTE_COUNT = 103;      
      RSA_R_BAD_SIGNATURE = 104;      
      RSA_R_BLOCK_TYPE_IS_NOT_01 = 106;      
      RSA_R_BLOCK_TYPE_IS_NOT_02 = 107;      
      RSA_R_DATA_GREATER_THAN_MOD_LEN = 108;      
      RSA_R_DATA_TOO_LARGE = 109;      
      RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 110;      
      RSA_R_DATA_TOO_LARGE_FOR_MODULUS = 132;      
      RSA_R_DATA_TOO_SMALL = 111;      
      RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE = 122;      
      RSA_R_DIGEST_DOES_NOT_MATCH = 158;      
      RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY = 112;      
      RSA_R_DMP1_NOT_CONGRUENT_TO_D = 124;      
      RSA_R_DMQ1_NOT_CONGRUENT_TO_D = 125;      
      RSA_R_D_E_NOT_CONGRUENT_TO_1 = 123;      
      RSA_R_FIRST_OCTET_INVALID = 133;      
      RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE = 144;      
      RSA_R_INVALID_DIGEST = 157;      
      RSA_R_INVALID_DIGEST_LENGTH = 143;      
      RSA_R_INVALID_HEADER = 137;      
      RSA_R_INVALID_LABEL = 160;      
      RSA_R_INVALID_MESSAGE_LENGTH = 131;      
      RSA_R_INVALID_MGF1_MD = 156;      
      RSA_R_INVALID_OAEP_PARAMETERS = 161;      
      RSA_R_INVALID_PADDING = 138;      
      RSA_R_INVALID_PADDING_MODE = 141;      
      RSA_R_INVALID_PSS_PARAMETERS = 149;      
      RSA_R_INVALID_PSS_SALTLEN = 146;      
      RSA_R_INVALID_SALT_LENGTH = 150;      
      RSA_R_INVALID_TRAILER = 139;      
      RSA_R_INVALID_X931_DIGEST = 142;      
      RSA_R_IQMP_NOT_INVERSE_OF_Q = 126;      
      RSA_R_KEY_SIZE_TOO_SMALL = 120;      
      RSA_R_LAST_OCTET_INVALID = 134;      
      RSA_R_MODULUS_TOO_LARGE = 105;      
      RSA_R_NO_PUBLIC_EXPONENT = 140;      
      RSA_R_NULL_BEFORE_BLOCK_MISSING = 113;      
      RSA_R_N_DOES_NOT_EQUAL_P_Q = 127;      
      RSA_R_OAEP_DECODING_ERROR = 121;      
      RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 148;      
      RSA_R_PADDING_CHECK_FAILED = 114;      
      RSA_R_PKCS_DECODING_ERROR = 159;      
      RSA_R_P_NOT_PRIME = 128;      
      RSA_R_Q_NOT_PRIME = 129;      
      RSA_R_RSA_OPERATIONS_NOT_SUPPORTED = 130;      
      RSA_R_SLEN_CHECK_FAILED = 136;      
      RSA_R_SLEN_RECOVERY_FAILED = 135;      
      RSA_R_SSLV3_ROLLBACK_ATTACK = 115;      
      RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 116;      
      RSA_R_UNKNOWN_ALGORITHM_TYPE = 117;      
      RSA_R_UNKNOWN_DIGEST = 166;      
      RSA_R_UNKNOWN_MASK_DIGEST = 151;      
      RSA_R_UNKNOWN_PADDING_TYPE = 118;      
      RSA_R_UNSUPPORTED_ENCRYPTION_TYPE = 162;      
      RSA_R_UNSUPPORTED_LABEL_SOURCE = 163;      
      RSA_R_UNSUPPORTED_MASK_ALGORITHM = 153;      
      RSA_R_UNSUPPORTED_MASK_PARAMETER = 154;      
      RSA_R_UNSUPPORTED_SIGNATURE_TYPE = 155;      
      RSA_R_VALUE_MISSING = 147;      
      RSA_R_WRONG_SIGNATURE_LENGTH = 119;      
{$define HEADER_DSA_H}    
{$define HEADER_DH_H}    
      OPENSSL_DH_MAX_MODULUS_BITS = 10000;      
      OPENSSL_DH_FIPS_MIN_MODULUS_BITS = 1024;      
      DH_FLAG_CACHE_MONT_P = $01;      
      DH_FLAG_NO_EXP_CONSTTIME = $00;      
      DH_FLAG_FIPS_METHOD = $0400;      
      DH_FLAG_NON_FIPS_ALLOW = $0400;

    const
      DH_GENERATOR_2 = 2;      
      DH_GENERATOR_5 = 5;      
      DH_CHECK_P_NOT_PRIME = $01;      
      DH_CHECK_P_NOT_SAFE_PRIME = $02;      
      DH_UNABLE_TO_CHECK_GENERATOR = $04;      
      DH_NOT_SUITABLE_GENERATOR = $08;      
      DH_CHECK_Q_NOT_PRIME = $10;      
      DH_CHECK_INVALID_Q_VALUE = $20;      
      DH_CHECK_INVALID_J_VALUE = $40;      
      DH_CHECK_PUBKEY_TOO_SMALL = $01;      
      DH_CHECK_PUBKEY_TOO_LARGE = $02;      
      DH_CHECK_PUBKEY_INVALID = $04;      
      DH_CHECK_P_NOT_STRONG_PRIME = DH_CHECK_P_NOT_SAFE_PRIME;      

    function  d2i_DHparams_bio(bp:PBIO;x:Ppointer) : Pointer;

    function  i2d_DHparams_bio(bp:PBIO;x:PByte) : cint;

    function  d2i_DHxparams_bio(bp:PBIO;x:Ppointer) : Pointer;

    function  i2d_DHxparams_bio(bp:PBIO;x:PByte) : cint;

type
 TDH_init_cb=function  (para1:PDH):cint;cdecl;
 TDH_key_cb=function  (key:pbyte; pub_key:PBIGNUM; dh:PDH):cint;cdecl;
 TDH_mod_exp_cb=function  (para1:PDH; para2:PBIGNUM; para3:PBIGNUM; para4:PBIGNUM; para5:PBIGNUM; para6:PBN_CTX; para7:PBN_MONT_CTX):cint;cdecl;
 TDH_params_cb=function  (para1:PDH; para2:cint; para3:cint; para4:PBN_GENCB):cint;cdecl;

function  DHparams_dup(para1:PDH):PDH;cdecl; external DLLUtilName;
function  DH_OpenSSL:PDH_METHOD;cdecl; external DLLUtilName;
procedure DH_set_default_method(meth:PDH_METHOD);cdecl; external DLLUtilName;
function  DH_get_default_method:PDH_METHOD;cdecl; external DLLUtilName;
function  DH_set_method(dh:PDH; meth:PDH_METHOD):cint;cdecl; external DLLUtilName;
function  DH_new_method(engine:PENGINE):PDH;cdecl; external DLLUtilName;
function  DH_new:PDH;cdecl; external DLLUtilName;
procedure DH_free(dh:PDH);cdecl; external DLLUtilName;
function  DH_up_ref(dh:PDH):cint;cdecl; external DLLUtilName;
function  DH_bits(dh:PDH):cint;cdecl; external DLLUtilName;
function  DH_size(dh:PDH):cint;cdecl; external DLLUtilName;
function  DH_security_bits(dh:PDH):cint;cdecl; external DLLUtilName;

  function  DH_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  DH_set_ex_data(d:PDH; idx:cint; arg:pointer):cint;cdecl; external DLLUtilName;
function  DH_get_ex_data(d:PDH; idx:cint):pointer;cdecl; external DLLUtilName;
function  DH_check_params(dh:PDH; ret:pcint):cint;cdecl; external DLLUtilName;
function  DH_check(dh:PDH; codes:pcint):cint;cdecl; external DLLUtilName;
function  DH_check_pub_key(dh:PDH; pub_key:PBIGNUM; codes:pcint):cint;cdecl; external DLLUtilName;
function  DH_generate_key(dh:PDH):cint;cdecl; external DLLUtilName;
function  DH_compute_key(key:pbyte; pub_key:PBIGNUM; dh:PDH):cint;cdecl; external DLLUtilName;
function  DH_compute_key_padded(key:pbyte; pub_key:PBIGNUM; dh:PDH):cint;cdecl; external DLLUtilName;
function  d2i_DHparams(a:PPDH; pp:Ppbyte; length:clong):PDH;cdecl; external DLLUtilName;
function  i2d_DHparams(a:PDH; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_DHxparams(a:PPDH; pp:Ppbyte; length:clong):PDH;cdecl; external DLLUtilName;
function  i2d_DHxparams(a:PDH; pp:Ppbyte):cint;cdecl; external DLLUtilName;
//function  DHparams_print_fp(fp:PFILE; x:PDH):cint;cdecl; external DLLUtilName;
function  DHparams_print(bp:PBIO; x:PDH):cint;cdecl; external DLLUtilName;
function  DH_get_1024_160:PDH;cdecl; external DLLUtilName;
function  DH_get_2048_224:PDH;cdecl; external DLLUtilName;
function  DH_get_2048_256:PDH;cdecl; external DLLUtilName;
function  DH_KDF_X9_42(_out:pbyte; outlen:size_t; Z:pbyte; Zlen:size_t; key_oid:PASN1_OBJECT; 
               ukm:pbyte; ukmlen:size_t; md:PEVP_MD):cint;cdecl; external DLLUtilName;
procedure DH_get0_pqg(dh:PDH; p:PPBIGNUM; q:PPBIGNUM; g:PPBIGNUM);cdecl; external DLLUtilName;
function  DH_set0_pqg(dh:PDH; p:PBIGNUM; q:PBIGNUM; g:PBIGNUM):cint;cdecl; external DLLUtilName;
procedure DH_get0_key(dh:PDH; pub_key:PPBIGNUM; priv_key:PPBIGNUM);cdecl; external DLLUtilName;
function  DH_set0_key(dh:PDH; pub_key:PBIGNUM; priv_key:PBIGNUM):cint;cdecl; external DLLUtilName;
procedure DH_clear_flags(dh:PDH; flags:cint);cdecl; external DLLUtilName;
function  DH_test_flags(dh:PDH; flags:cint):cint;cdecl; external DLLUtilName;
procedure DH_set_flags(dh:PDH; flags:cint);cdecl; external DLLUtilName;
function  DH_get0_engine(d:PDH):PENGINE;cdecl; external DLLUtilName;
function  DH_get_length(dh:PDH):clong;cdecl; external DLLUtilName;
function  DH_set_length(dh:PDH; length:clong):cint;cdecl; external DLLUtilName;
function  DH_meth_new(name:pbyte; flags:cint):PDH_METHOD;cdecl; external DLLUtilName;
procedure DH_meth_free(dhm:PDH_METHOD);cdecl; external DLLUtilName;
function  DH_meth_dup(dhm:PDH_METHOD):PDH_METHOD;cdecl; external DLLUtilName;
function  DH_meth_get0_name(dhm:PDH_METHOD):pbyte;cdecl; external DLLUtilName;
function  DH_meth_set1_name(dhm:PDH_METHOD; name:pbyte):cint;cdecl; external DLLUtilName;
function  DH_meth_get_flags(dhm:PDH_METHOD):cint;cdecl; external DLLUtilName;
function  DH_meth_set_flags(dhm:PDH_METHOD; flags:cint):cint;cdecl; external DLLUtilName;
function  DH_meth_get0_app_data(dhm:PDH_METHOD):pointer;cdecl; external DLLUtilName;
function  DH_meth_set0_app_data(dhm:PDH_METHOD; app_data:pointer):cint;cdecl; external DLLUtilName;
function  DH_meth_get_generate_key(dhm:PDH_METHOD):TDH_init_cb;cdecl; external DLLUtilName;
function  DH_meth_set_generate_key(dhm:PDH_METHOD; generate_key:TDH_init_cb):cint;cdecl; external DLLUtilName;
function  DH_meth_get_compute_key(dhm:PDH_METHOD):TDH_key_cb;cdecl; external DLLUtilName;
function  DH_meth_set_compute_key(dhm:PDH_METHOD; compute_key:TDH_key_cb):cint;cdecl; external DLLUtilName;
function  DH_meth_get_bn_mod_exp(dhm:PDH_METHOD):TDH_mod_exp_cb;cdecl; external DLLUtilName;
function  DH_meth_set_bn_mod_exp(dhm:PDH_METHOD; bn_mod_exp:TDH_mod_exp_cb):cint;cdecl; external DLLUtilName;
function  DH_meth_get_init(dhm:PDH_METHOD):TDH_init_cb;cdecl; external DLLUtilName;
function  DH_meth_set_init(dhm:PDH_METHOD; init:TDH_init_cb):cint;cdecl; external DLLUtilName;
function  DH_meth_get_finish(dhm:PDH_METHOD):TDH_init_cb;cdecl; external DLLUtilName;
function  DH_meth_set_finish(dhm:PDH_METHOD; finish:TDH_init_cb):cint;cdecl; external DLLUtilName;
function  DH_meth_get_generate_params(dhm:PDH_METHOD):TDH_params_cb;cdecl; external DLLUtilName;
function  DH_meth_set_generate_params(dhm:PDH_METHOD; generate_params:TDH_params_cb):cint;cdecl; external DLLUtilName;

    function  EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx:PEVP_PKEY_CTX;len : cint) : cint;

    function  EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx:PEVP_PKEY_CTX;len : cint) : cint;

    function  EVP_PKEY_CTX_set_dh_paramgen_type(ctx:PEVP_PKEY_CTX;typ : cint) : cint;

    function  EVP_PKEY_CTX_set_dh_paramgen_generator(ctx:PEVP_PKEY_CTX;gen : cint) : cint;

    function  EVP_PKEY_CTX_set_dh_rfc5114(ctx:PEVP_PKEY_CTX;gen : cint) : cint;

    function  EVP_PKEY_CTX_set_dhx_rfc5114(ctx:PEVP_PKEY_CTX;gen : cint) : cint;

    function  EVP_PKEY_CTX_set_dh_kdf_type(ctx:PEVP_PKEY_CTX;kdf : cint) : cint;

    function  EVP_PKEY_CTX_get_dh_kdf_type(ctx : PEVP_PKEY_CTX) : cint;

    function  EVP_PKEY_CTX_set0_dh_kdf_oid(ctx : PEVP_PKEY_CTX;oid : Pointer) : cint;

    function  EVP_PKEY_CTX_get0_dh_kdf_oid(ctx : PEVP_PKEY_CTX;poid : Pointer) : cint;

    function  EVP_PKEY_CTX_set_dh_kdf_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint;

    function  EVP_PKEY_CTX_get_dh_kdf_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint;

    function  EVP_PKEY_CTX_set_dh_kdf_outlen(ctx : PEVP_PKEY_CTX;len : cint) : cint;

    function  EVP_PKEY_CTX_get_dh_kdf_outlen(ctx : PEVP_PKEY_CTX;plen : Pointer) : cint;

    function  EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx : PEVP_PKEY_CTX;p:Pointer;plen : cint) : cint;

    function  EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx : PEVP_PKEY_CTX;p : Pointer) : cint;

    const
      EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN = EVP_PKEY_ALG_CTRL+1;      
      EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR = EVP_PKEY_ALG_CTRL+2;      
      EVP_PKEY_CTRL_DH_RFC5114 = EVP_PKEY_ALG_CTRL+3;      
      EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN = EVP_PKEY_ALG_CTRL+4;      
      EVP_PKEY_CTRL_DH_PARAMGEN_TYPE = EVP_PKEY_ALG_CTRL+5;      
      EVP_PKEY_CTRL_DH_KDF_TYPE = EVP_PKEY_ALG_CTRL+6;      
      EVP_PKEY_CTRL_DH_KDF_MD = EVP_PKEY_ALG_CTRL+7;      
      EVP_PKEY_CTRL_GET_DH_KDF_MD = EVP_PKEY_ALG_CTRL+8;      
      EVP_PKEY_CTRL_DH_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+9;      
      EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+10;      
      EVP_PKEY_CTRL_DH_KDF_UKM = EVP_PKEY_ALG_CTRL+11;      
      EVP_PKEY_CTRL_GET_DH_KDF_UKM = EVP_PKEY_ALG_CTRL+12;      
      EVP_PKEY_CTRL_DH_KDF_OID = EVP_PKEY_ALG_CTRL+13;      
      EVP_PKEY_CTRL_GET_DH_KDF_OID = EVP_PKEY_ALG_CTRL+14;      
      EVP_PKEY_DH_KDF_NONE = 1;      
      EVP_PKEY_DH_KDF_X9_42 = 2;      

function  ERR_load_DH_strings:cint;cdecl; external DLLUtilName;

    const
      DH_F_COMPUTE_KEY = 102;      
      DH_F_DHPARAMS_PRINT_FP = 101;      
      DH_F_DH_BUILTIN_GENPARAMS = 106;      
      DH_F_DH_CMS_DECRYPT = 114;      
      DH_F_DH_CMS_SET_PEERKEY = 115;      
      DH_F_DH_CMS_SET_SHARED_INFO = 116;      
      DH_F_DH_METH_DUP = 117;      
      DH_F_DH_METH_NEW = 118;      
      DH_F_DH_METH_SET1_NAME = 119;      
      DH_F_DH_NEW_METHOD = 105;      
      DH_F_DH_PARAM_DECODE = 107;      
      DH_F_DH_PRIV_DECODE = 110;      
      DH_F_DH_PRIV_ENCODE = 111;      
      DH_F_DH_PUB_DECODE = 108;      
      DH_F_DH_PUB_ENCODE = 109;      
      DH_F_DO_DH_PRINT = 100;      
      DH_F_GENERATE_KEY = 103;      
      DH_F_PKEY_DH_DERIVE = 112;      
      DH_F_PKEY_DH_KEYGEN = 113;      
      DH_R_BAD_GENERATOR = 101;      
      DH_R_BN_DECODE_ERROR = 109;      
      DH_R_BN_ERROR = 106;      
      DH_R_DECODE_ERROR = 104;      
      DH_R_INVALID_PUBKEY = 102;      
      DH_R_KDF_PARAMETER_ERROR = 112;      
      DH_R_KEYS_NOT_SET = 108;      
      DH_R_MODULUS_TOO_LARGE = 103;      
      DH_R_NO_PARAMETERS_SET = 107;      
      DH_R_NO_PRIVATE_VALUE = 100;      
      DH_R_PARAMETER_ENCODING_ERROR = 105;      
      DH_R_PEER_KEY_ERROR = 111;      
      DH_R_SHARED_INFO_ERROR = 113;      
      OPENSSL_DSA_MAX_MODULUS_BITS = 10000;      
      OPENSSL_DSA_FIPS_MIN_MODULUS_BITS = 1024;      
      DSA_FLAG_CACHE_MONT_P = $01;      
      DSA_FLAG_NO_EXP_CONSTTIME = $00;      
      DSA_FLAG_FIPS_METHOD = $0400;      
      DSA_FLAG_NON_FIPS_ALLOW = $0400;      
      DSA_FLAG_FIPS_CHECKED = $0800;

    function  d2i_DSAparams_bio(bp:PBIO;x:Ppointer) : Pointer;

    function  i2d_DSAparams_bio(bp:PBIO;x:PByte) : cint;

function  DSAparams_dup(x:PDSA):PDSA;cdecl; external DLLUtilName;
function  DSA_SIG_new:PDSA_SIG;cdecl; external DLLUtilName;
procedure DSA_SIG_free(a:PDSA_SIG);cdecl; external DLLUtilName;
function  i2d_DSA_SIG(a:PDSA_SIG; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_DSA_SIG(v:PPDSA_SIG; pp:Ppbyte; length:clong):PDSA_SIG;cdecl; external DLLUtilName;
procedure DSA_SIG_get0(sig:PDSA_SIG; pr:PPBIGNUM; ps:PPBIGNUM);cdecl; external DLLUtilName;
function  DSA_SIG_set0(sig:PDSA_SIG; r:PBIGNUM; s:PBIGNUM):cint;cdecl; external DLLUtilName;
function  DSA_do_sign(dgst:pbyte; dlen:cint; dsa:PDSA):PDSA_SIG;cdecl; external DLLUtilName;
function  DSA_do_verify(dgst:pbyte; dgst_len:cint; sig:PDSA_SIG; dsa:PDSA):cint;cdecl; external DLLUtilName;
function  DSA_OpenSSL:PDSA_METHOD;cdecl; external DLLUtilName;
procedure DSA_set_default_method(para1:PDSA_METHOD);cdecl; external DLLUtilName;
function  DSA_get_default_method:PDSA_METHOD;cdecl; external DLLUtilName;
function  DSA_set_method(dsa:PDSA; para2:PDSA_METHOD):cint;cdecl; external DLLUtilName;
function  DSA_get_method(d:PDSA):PDSA_METHOD;cdecl; external DLLUtilName;
function  DSA_new:PDSA;cdecl; external DLLUtilName;
function  DSA_new_method(engine:PENGINE):PDSA;cdecl; external DLLUtilName;
procedure DSA_free(r:PDSA);cdecl; external DLLUtilName;
function  DSA_up_ref(r:PDSA):cint;cdecl; external DLLUtilName;
function  DSA_size(para1:PDSA):cint;cdecl; external DLLUtilName;
function  DSA_bits(d:PDSA):cint;cdecl; external DLLUtilName;
function  DSA_security_bits(d:PDSA):cint;cdecl; external DLLUtilName;
function  DSA_sign_setup(dsa:PDSA; ctx_in:PBN_CTX; kinvp:PPBIGNUM; rp:PPBIGNUM):cint;cdecl; external DLLUtilName;
function  DSA_sign(_type:cint; dgst:pbyte; dlen:cint; sig:pbyte; siglen:pcuint; 
               dsa:PDSA):cint;cdecl; external DLLUtilName;
function  DSA_verify(_type:cint; dgst:pbyte; dgst_len:cint; sigbuf:pbyte; siglen:cint; 
               dsa:PDSA):cint;cdecl; external DLLUtilName;

    function  DSA_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  DSA_set_ex_data(d:PDSA; idx:cint; arg:pointer):cint;cdecl; external DLLUtilName;
function  DSA_get_ex_data(d:PDSA; idx:cint):pointer;cdecl; external DLLUtilName;
function  d2i_DSAPublicKey(a:PPDSA; pp:Ppbyte; length:clong):PDSA;cdecl; external DLLUtilName;
function  d2i_DSAPrivateKey(a:PPDSA; pp:Ppbyte; length:clong):PDSA;cdecl; external DLLUtilName;
function  d2i_DSAparams(a:PPDSA; pp:Ppbyte; length:clong):PDSA;cdecl; external DLLUtilName;
function  DSA_generate_key(a:PDSA):cint;cdecl; external DLLUtilName;
function  i2d_DSAPublicKey(a:PDSA; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  i2d_DSAPrivateKey(a:PDSA; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  i2d_DSAparams(a:PDSA; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  DSAparams_print(bp:PBIO; x:PDSA):cint;cdecl; external DLLUtilName;
function  DSA_print(bp:PBIO; x:PDSA; off:cint):cint;cdecl; external DLLUtilName;
//function  DSAparams_print_fp(fp:PFILE; x:PDSA):cint;cdecl; external DLLUtilName;
//function  DSA_print_fp(bp:PFILE; x:PDSA; off:cint):cint;cdecl; external DLLUtilName;

    const
      DSS_prime_checks = 50;      

function  DSA_dup_DH(r:PDSA):PDH;cdecl; external DLLUtilName;

    function  EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx:PEVP_PKEY_CTX; nbits : cint) : cint;

    const
      EVP_PKEY_CTRL_DSA_PARAMGEN_BITS = EVP_PKEY_ALG_CTRL+1;      
      EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = EVP_PKEY_ALG_CTRL+2;      
      EVP_PKEY_CTRL_DSA_PARAMGEN_MD = EVP_PKEY_ALG_CTRL+3;      

type
 TDSA_sign_cb=function  (para1:pbyte; para2:cint; para3:PDSA):PDSA_SIG;cdecl;
 TDSA_sign_setup_cb=function  (para1:PDSA; para2:PBN_CTX; para3:PPBIGNUM; para4:PPBIGNUM):cint;cdecl;
 TDSA_verify_cb=function  (para1:pbyte; para2:cint; para3:PDSA_SIG; para4:PDSA):cint;cdecl;
 TDSA_mod_exp_cb=function  (para1:PDSA; para2:PBIGNUM; para3:PBIGNUM; para4:PBIGNUM; para5:PBIGNUM; para6:PBIGNUM; para7:PBIGNUM; para8:PBN_CTX; para9:PBN_MONT_CTX):cint;cdecl;
 TDSA_bn_mod_exp_cb=function  (para1:PDSA; para2:PBIGNUM; para3:PBIGNUM; para4:PBIGNUM; para5:PBIGNUM; para6:PBN_CTX; para7:PBN_MONT_CTX):cint;cdecl;
 TDSA_init_cb=function  (para1:PDSA):cint;cdecl;
 TDSA_paramgen_cb=function  (para1:PDSA; para2:cint; para3:pbyte; para4:cint; para5:pcint; para6:pculong; para7:PBN_GENCB):cint;cdecl;

procedure DSA_get0_pqg(d:PDSA; p:PPBIGNUM; q:PPBIGNUM; g:PPBIGNUM);cdecl; external DLLUtilName;
function  DSA_set0_pqg(d:PDSA; p:PBIGNUM; q:PBIGNUM; g:PBIGNUM):cint;cdecl; external DLLUtilName;
procedure DSA_get0_key(d:PDSA; pub_key:PPBIGNUM; priv_key:PPBIGNUM);cdecl; external DLLUtilName;
function  DSA_set0_key(d:PDSA; pub_key:PBIGNUM; priv_key:PBIGNUM):cint;cdecl; external DLLUtilName;
procedure DSA_clear_flags(d:PDSA; flags:cint);cdecl; external DLLUtilName;
function  DSA_test_flags(d:PDSA; flags:cint):cint;cdecl; external DLLUtilName;
procedure DSA_set_flags(d:PDSA; flags:cint);cdecl; external DLLUtilName;
function  DSA_get0_engine(d:PDSA):PENGINE;cdecl; external DLLUtilName;
function  DSA_meth_new(name:pbyte; flags:cint):PDSA_METHOD;cdecl; external DLLUtilName;
procedure DSA_meth_free(dsam:PDSA_METHOD);cdecl; external DLLUtilName;
function  DSA_meth_dup(dsam:PDSA_METHOD):PDSA_METHOD;cdecl; external DLLUtilName;
function  DSA_meth_get0_name(dsam:PDSA_METHOD):pbyte;cdecl; external DLLUtilName;
function  DSA_meth_set1_name(dsam:PDSA_METHOD; name:pbyte):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_flags(dsam:PDSA_METHOD):cint;cdecl; external DLLUtilName;
function  DSA_meth_set_flags(dsam:PDSA_METHOD; flags:cint):cint;cdecl; external DLLUtilName;
function  DSA_meth_get0_app_data(dsam:PDSA_METHOD):pointer;cdecl; external DLLUtilName;
function  DSA_meth_set0_app_data(dsam:PDSA_METHOD; app_data:pointer):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_sign(dsam:PDSA_METHOD):TDSA_sign_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_sign(dsam:PDSA_METHOD; sign:TDSA_sign_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_sign_setup(dsam:PDSA_METHOD):TDSA_sign_setup_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_sign_setup(dsam:PDSA_METHOD; sign_setup:TDSA_sign_setup_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_verify(dsam:PDSA_METHOD):TDSA_verify_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_verify(dsam:PDSA_METHOD; verify:TDSA_verify_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_mod_exp(dsam:PDSA_METHOD):TDSA_mod_exp_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_mod_exp(dsam:PDSA_METHOD; mod_exp:TDSA_mod_exp_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_bn_mod_exp(dsam:PDSA_METHOD):TDSA_bn_mod_exp_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_bn_mod_exp(dsam:PDSA_METHOD; bn_mod_exp:TDSA_bn_mod_exp_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_init(dsam:PDSA_METHOD):TDSA_init_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_init(dsam:PDSA_METHOD; init:TDSA_init_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_finish(dsam:PDSA_METHOD):TDSA_init_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_finish(dsam:PDSA_METHOD; finish:TDSA_init_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_paramgen(dsam:PDSA_METHOD):TDSA_paramgen_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_paramgen(dsam:PDSA_METHOD; paramgen:TDSA_paramgen_cb):cint;cdecl; external DLLUtilName;
function  DSA_meth_get_keygen(dsam:PDSA_METHOD):TDSA_init_cb;cdecl; external DLLUtilName;
function  DSA_meth_set_keygen(dsam:PDSA_METHOD; keygen:TDSA_init_cb):cint;cdecl; external DLLUtilName;
function  ERR_load_DSA_strings:cint;cdecl; external DLLUtilName;

    const
      DSA_F_DSAPARAMS_PRINT = 100;      
      DSA_F_DSAPARAMS_PRINT_FP = 101;      
      DSA_F_DSA_BUILTIN_PARAMGEN = 125;      
      DSA_F_DSA_BUILTIN_PARAMGEN2 = 126;      
      DSA_F_DSA_DO_SIGN = 112;      
      DSA_F_DSA_DO_VERIFY = 113;      
      DSA_F_DSA_METH_DUP = 127;      
      DSA_F_DSA_METH_NEW = 128;      
      DSA_F_DSA_METH_SET1_NAME = 129;      
      DSA_F_DSA_NEW_METHOD = 103;      
      DSA_F_DSA_PARAM_DECODE = 119;      
      DSA_F_DSA_PRINT_FP = 105;      
      DSA_F_DSA_PRIV_DECODE = 115;      
      DSA_F_DSA_PRIV_ENCODE = 116;      
      DSA_F_DSA_PUB_DECODE = 117;      
      DSA_F_DSA_PUB_ENCODE = 118;      
      DSA_F_DSA_SIGN = 106;      
      DSA_F_DSA_SIGN_SETUP = 107;      
      DSA_F_DSA_SIG_NEW = 102;      
      DSA_F_OLD_DSA_PRIV_DECODE = 122;      
      DSA_F_PKEY_DSA_CTRL = 120;      
      DSA_F_PKEY_DSA_KEYGEN = 121;      
      DSA_R_BAD_Q_VALUE = 102;      
      DSA_R_BN_DECODE_ERROR = 108;      
      DSA_R_BN_ERROR = 109;      
      DSA_R_DECODE_ERROR = 104;      
      DSA_R_INVALID_DIGEST_TYPE = 106;      
      DSA_R_INVALID_PARAMETERS = 112;      
      DSA_R_MISSING_PARAMETERS = 101;      
      DSA_R_MODULUS_TOO_LARGE = 103;      
      DSA_R_NO_PARAMETERS_SET = 107;      
      DSA_R_PARAMETER_ENCODING_ERROR = 105;      
      DSA_R_Q_NOT_PRIME = 113;      
      DSA_R_SEED_LEN_SMALL = 110;      
{$define HEADER_SHA_H}
    type
      SHA_LONG = cuint;

    const
      SHA_LBLOCK = 16;
      SHA_CBLOCK=(SHA_LBLOCK*4);
      SHA_LAST_BLOCK = SHA_CBLOCK-8;      
      SHA_DIGEST_LENGTH = 20;

    type
      PSHAstate= ^TSHAstate_st;
      TSHAstate_st = record
          h0 : cuint;
          h1 : cuint;
          h2 : cuint;
          h3 : cuint;
          h4 : cuint;
          Nl : cuint;
          Nh : cuint;
          data : array[0..15] of cuint;
          num : cuint;
        end;
      TSHA_CTX = TSHAstate_st;
      PSHA_CTX = ^TSHA_CTX;

function  SHA1_Init(c:PSHA_CTX):cint;cdecl; external DLLUtilName;
function  SHA1_Update(c:PSHA_CTX; data:pointer; len:size_t):cint;cdecl; external DLLUtilName;
function  SHA1_Final(md:pbyte; c:PSHA_CTX):cint;cdecl; external DLLUtilName;
function  SHA1(d:pbyte; n:size_t; md:pbyte):pbyte;cdecl; external DLLUtilName;
procedure SHA1_Transform(c:PSHA_CTX; data:pbyte);cdecl; external DLLUtilName;

    type
      PSHA256state= ^TSHA256state_st;
      TSHA256state_st = record
          h : array[0..7] of cuint;
          Nl : cuint;
          Nh : cuint;
          data : array[0..15] of cuint;
          num : cuint;
          md_len : cuint;
        end;
      TSHA256_CTX = TSHA256state_st;
      PSHA256_CTX = ^TSHA256_CTX;

function  SHA224_Init(c:PSHA256_CTX):cint;cdecl; external DLLUtilName;
function  SHA224_Update(c:PSHA256_CTX; data:pointer; len:size_t):cint;cdecl; external DLLUtilName;
function  SHA224_Final(md:pbyte; c:PSHA256_CTX):cint;cdecl; external DLLUtilName;
function  SHA224(d:pbyte; n:size_t; md:pbyte):pbyte;cdecl; external DLLUtilName;
function  SHA256_Init(c:PSHA256_CTX):cint;cdecl; external DLLUtilName;
function  SHA256_Update(c:PSHA256_CTX; data:pointer; len:size_t):cint;cdecl; external DLLUtilName;
function  SHA256_Final(md:pbyte; c:PSHA256_CTX):cint;cdecl; external DLLUtilName;
function  SHA256(d:pbyte; n:size_t; md:pbyte):pbyte;cdecl; external DLLUtilName;
procedure SHA256_Transform(c:PSHA256_CTX; data:pbyte);cdecl; external DLLUtilName;

    const
      SHA224_DIGEST_LENGTH = 28;      
      SHA256_DIGEST_LENGTH = 32;      
      SHA384_DIGEST_LENGTH = 48;      
      SHA512_DIGEST_LENGTH = 64;
    type
      SHA_LONG64 = Uint64;
      PSHA512state= ^TSHA512state_st;
      TSHA512state_st = record
          h : array[0..7] of culonglong;
          Nl : culonglong;
          Nh : culonglong;
          u : record
              case longint of
                0 : ( d : array[0..15] of culonglong );
                1 : ( p : array[0..(16*8)-1] of byte );
              end;
          num : cuint;
          md_len : cuint;
        end;
      TSHA512_CTX = TSHA512state_st;
      PSHA512_CTX = ^TSHA512_CTX;

function  SHA384_Init(c:PSHA512_CTX):cint;cdecl; external DLLUtilName;
function  SHA384_Update(c:PSHA512_CTX; data:pointer; len:size_t):cint;cdecl; external DLLUtilName;
function  SHA384_Final(md:pbyte; c:PSHA512_CTX):cint;cdecl; external DLLUtilName;
function  SHA384(d:pbyte; n:size_t; md:pbyte):pbyte;cdecl; external DLLUtilName;
function  SHA512_Init(c:PSHA512_CTX):cint;cdecl; external DLLUtilName;
function  SHA512_Update(c:PSHA512_CTX; data:pointer; len:size_t):cint;cdecl; external DLLUtilName;
function  SHA512_Final(md:pbyte; c:PSHA512_CTX):cint;cdecl; external DLLUtilName;
function  SHA512(d:pbyte; n:size_t; md:pbyte):pbyte;cdecl; external DLLUtilName;
procedure SHA512_Transform(c:PSHA512_CTX; data:pbyte);cdecl; external DLLUtilName;

    const
      X509_FILETYPE_PEM = 1;      
      X509_FILETYPE_ASN1 = 2;      
      X509_FILETYPE_DEFAULT = 3;      
      X509v3_KU_DIGITAL_SIGNATURE = $0080;      
      X509v3_KU_NON_REPUDIATION = $0040;      
      X509v3_KU_KEY_ENCIPHERMENT = $0020;      
      X509v3_KU_DATA_ENCIPHERMENT = $0010;      
      X509v3_KU_KEY_AGREEMENT = $0008;      
      X509v3_KU_KEY_CERT_SIGN = $0004;      
      X509v3_KU_CRL_SIGN = $0002;      
      X509v3_KU_ENCIPHER_ONLY = $0001;      
      X509v3_KU_DECIPHER_ONLY = $8000;      
      X509v3_KU_UNDEF = $ffff;

      SSL_FILETYPE_ASN1 = X509_FILETYPE_ASN1;
      SSL_FILETYPE_PEM = X509_FILETYPE_PEM;

    type
      PPX509_VAL=^PX509_VAL;
      PX509_val= ^TX509_val_st;
      TX509_val_st = record
          notBefore : PASN1_TIME;
          notAfter : PASN1_TIME;
        end;
      TX509_VAL = TX509_val_st;

      Pstack_st_X509_NAME_ENTRY = ^Tstack_st_X509_NAME_ENTRY;
      Tstack_st_X509_NAME_ENTRY = record
          {undefined structure}
      end;

      PX509_NAME_ENTRY=Pstack_st_X509_NAME_ENTRY;
      PPX509_NAME_ENTRY=^PX509_NAME_ENTRY;

      Pstack_st_X509_NAME = ^Tstack_st_X509_NAME;
      Tstack_st_X509_NAME = record
          {undefined structure}
      end;

      PX509_NAME=Pstack_st_X509_NAME;
      PPX509_NAME=^PX509_NAME;

      Tsk_X509_NAME_ENTRY_compfunc = function  (a:PPX509_NAME_ENTRY; b:PPX509_NAME_ENTRY):cint;cdecl;

      Tsk_X509_NAME_ENTRY_freefunc = procedure (a:PX509_NAME_ENTRY);cdecl;

      Tsk_X509_NAME_ENTRY_copyfunc = function  (a:PX509_NAME_ENTRY):PX509_NAME_ENTRY;cdecl;

      Tsk_X509_NAME_compfunc = function  (a:PPX509_NAME; b:PPX509_NAME):cint;cdecl;

      Tsk_X509_NAME_freefunc = procedure (a:PX509_NAME);cdecl;

      Tsk_X509_NAME_copyfunc = function  (a:PX509_NAME):PX509_NAME;cdecl;

    const
      X509_EX_V_INIT = $0001;

    type
      Pstack_st_X509_EXTENSION = ^Tstack_st_X509_EXTENSION;
      Tstack_st_X509_EXTENSION = record
          {undefined structure}
        end;
      PX509_EXTENSION=Pstack_st_X509_EXTENSION;
      PPX509_EXTENSION=^PX509_EXTENSION;

      Tsk_X509_EXTENSION_compfunc = function  (a:PPX509_EXTENSION; b:PPX509_EXTENSION):cint;cdecl;

      Tsk_X509_EXTENSION_freefunc = procedure (a:PX509_EXTENSION);cdecl;

      Tsk_X509_EXTENSION_copyfunc = function  (a:PX509_EXTENSION):PX509_EXTENSION;cdecl;

      Pstack_st_X509_ATTRIBUTE = ^Tstack_st_X509_ATTRIBUTE;
      Tstack_st_X509_ATTRIBUTE = record
          {undefined structure}
        end;
      PX509_ATTRIBUTE=Pstack_st_X509_ATTRIBUTE;
      PPX509_ATTRIBUTE=^PX509_ATTRIBUTE;

      Tsk_X509_ATTRIBUTE_compfunc = function  (a:PPX509_ATTRIBUTE; b:PPX509_ATTRIBUTE):cint;cdecl;

      Tsk_X509_ATTRIBUTE_freefunc = procedure (a:PX509_ATTRIBUTE);cdecl;

      Tsk_X509_ATTRIBUTE_copyfunc = function  (a:PX509_ATTRIBUTE):PX509_ATTRIBUTE;cdecl;

      Tsk_X509_compfunc = function  (a:PPX509; b:PPX509):cint;cdecl;

      Tsk_X509_freefunc = procedure (a:PX509);cdecl;

      Tsk_X509_copyfunc = function  (a:PX509):PX509;cdecl;

    type
      Pstack_st_X509_TRUST = ^Tstack_st_X509_TRUST;
      Tstack_st_X509_TRUST = record
          {undefined structure}
        end;
      PX509_TRUST=Pstack_st_X509_TRUST;
      PPX509_TRUST=^PX509_TRUST;

      Tsk_X509_TRUST_compfunc = function  (a:PPX509_TRUST; b:PPX509_TRUST):cint;cdecl;

      Tsk_X509_TRUST_freefunc = procedure (a:PX509_TRUST);cdecl;

      Tsk_X509_TRUST_copyfunc = function  (a:PX509_TRUST):PX509_TRUST;cdecl;

    const
      X509_TRUST_COMPAT = 1;      
      X509_TRUST_SSL_CLIENT = 2;      
      X509_TRUST_SSL_SERVER = 3;      
      X509_TRUST_EMAIL = 4;      
      X509_TRUST_OBJECT_SIGN = 5;      
      X509_TRUST_OCSP_SIGN = 6;      
      X509_TRUST_OCSP_REQUEST = 7;      
      X509_TRUST_TSA = 8;      
      X509_TRUST_MIN = 1;      
      X509_TRUST_MAX = 8;      
      X509_TRUST_DYNAMIC = 1 shl 0;      
      X509_TRUST_DYNAMIC_NAME = 1 shl 1;      
      X509_TRUST_NO_SS_COMPAT = 1 shl 2;      
      X509_TRUST_DO_SS_COMPAT = 1 shl 3;      
      X509_TRUST_OK_ANY_EKU = 1 shl 4;      
      X509_TRUST_TRUSTED = 1;      
      X509_TRUST_REJECTED = 2;      
      X509_TRUST_UNTRUSTED = 3;      
      X509_FLAG_COMPAT = 0;      
      X509_FLAG_NO_HEADER = 1;      
      X509_FLAG_NO_VERSION = 1 shl 1;      
      X509_FLAG_NO_SERIAL = 1 shl 2;      
      X509_FLAG_NO_SIGNAME = 1 shl 3;      
      X509_FLAG_NO_ISSUER = 1 shl 4;      
      X509_FLAG_NO_VALIDITY = 1 shl 5;      
      X509_FLAG_NO_SUBJECT = 1 shl 6;      
      X509_FLAG_NO_PUBKEY = 1 shl 7;      
      X509_FLAG_NO_EXTENSIONS = 1 shl 8;      
      X509_FLAG_NO_SIGDUMP = 1 shl 9;      
      X509_FLAG_NO_AUX = 1 shl 10;      
      X509_FLAG_NO_ATTRIBUTES = 1 shl 11;      
      X509_FLAG_NO_IDS = 1 shl 12;      
      XN_FLAG_SEP_MASK = $f shl 16;      
      XN_FLAG_COMPAT = 0;      
      XN_FLAG_SEP_COMMA_PLUS = 1 shl 16;      
      XN_FLAG_SEP_CPLUS_SPC = 2 shl 16;      
      XN_FLAG_SEP_SPLUS_SPC = 3 shl 16;      
      XN_FLAG_SEP_MULTILINE = 4 shl 16;      
      XN_FLAG_DN_REV = 1 shl 20;      
      XN_FLAG_FN_MASK = $3 shl 21;      
      XN_FLAG_FN_SN = 0;      
      XN_FLAG_FN_LN = 1 shl 21;      
      XN_FLAG_FN_OID = 2 shl 21;      
      XN_FLAG_FN_NONE = 3 shl 21;      
      XN_FLAG_SPC_EQ = 1 shl 23;      
      XN_FLAG_DUMP_UNKNOWN_FIELDS = 1 shl 24;      
      XN_FLAG_FN_ALIGN = 1 shl 25;      
      XN_FLAG_RFC2253 = (((ASN1_STRFLGS_RFC2253 or XN_FLAG_SEP_COMMA_PLUS) or XN_FLAG_DN_REV) or XN_FLAG_FN_SN) or XN_FLAG_DUMP_UNKNOWN_FIELDS;      
      XN_FLAG_ONELINE = (((ASN1_STRFLGS_RFC2253 or ASN1_STRFLGS_ESC_QUOTE) or XN_FLAG_SEP_CPLUS_SPC) or XN_FLAG_SPC_EQ) or XN_FLAG_FN_SN;      
      XN_FLAG_MULTILINE = ((((ASN1_STRFLGS_ESC_CTRL or ASN1_STRFLGS_ESC_MSB) or XN_FLAG_SEP_MULTILINE) or XN_FLAG_SPC_EQ) or XN_FLAG_FN_LN) or XN_FLAG_FN_ALIGN;      

    type
      Pstack_st_X509_REVOKED = ^Tstack_st_X509_REVOKED;
      Tstack_st_X509_REVOKED = record
          {undefined structure}
        end;
      PX509_REVOKED=Pstack_st_X509_REVOKED;
      PPX509_REVOKED=^PX509_REVOKED;

      Tsk_X509_REVOKED_compfunc = function  (a:PPX509_REVOKED; b:PPX509_REVOKED):cint;cdecl;

      Tsk_X509_REVOKED_freefunc = procedure (a:PX509_REVOKED);cdecl;

      Tsk_X509_REVOKED_copyfunc = function  (a:PX509_REVOKED):PX509_REVOKED;cdecl;

      Pstack_st_X509_CRL = ^Tstack_st_X509_CRL;
      Tstack_st_X509_CRL = record
          {undefined structure}
        end;
      PX509_CRL=Pstack_st_X509_CRL;
      PPX509_CRL=^PX509_CRL;

      Tsk_X509_CRL_compfunc = function  (a:PPX509_CRL; b:PPX509_CRL):cint;cdecl;

      Tsk_X509_CRL_freefunc = procedure (a:PX509_CRL);cdecl;

      Tsk_X509_CRL_copyfunc = function  (a:PX509_CRL):PX509_CRL;cdecl;

    type
      PX509_info= ^TX509_info_st;
      PPX509_INFO=^PX509_INFO;
      TX509_info_st = record
          x509 : PX509;
          crl : PX509_CRL;
          x_pkey : PX509_PKEY;
          enc_cipher : TEVP_CIPHER_INFO;
          enc_len : cint;
          enc_data : pbyte;
        end;
      Pstack_st_X509_INFO = ^Tstack_st_X509_INFO;
      Tstack_st_X509_INFO = record
          {undefined structure}
        end;


      Tsk_X509_INFO_compfunc = function  (a:PPX509_INFO; b:PPX509_INFO):cint;cdecl;

      Tsk_X509_INFO_freefunc = procedure (a:PX509_INFO);cdecl;

      Tsk_X509_INFO_copyfunc = function  (a:PX509_INFO):PX509_INFO;cdecl;

    type
      PPNETSCAPE_SPKI=^PNETSCAPE_SPKI;
      PNetscape_spki= ^TNetscape_spki_st;
      TNetscape_spki_st = record
          spkac : PNETSCAPE_SPKAC;
          sig_algor : TX509_algor_st;
          signature : PASN1_BIT_STRING;
        end;

      PNetscape_certificate_sequence = ^TNetscape_certificate_sequence;
      TNetscape_certificate_sequence = record
          _type : PASN1_OBJECT;
          certs : Pstack_st_X509;
        end;
      TNETSCAPE_CERT_SEQUENCE = TNetscape_certificate_sequence;
      PNETSCAPE_CERT_SEQUENCE = ^TNETSCAPE_CERT_SEQUENCE;
      PPNETSCAPE_CERT_SEQUENCE=^PNETSCAPE_CERT_SEQUENCE;

      PPPBEPARAM=^PPBEPARAM;
      PPBEPARAM= ^TPBEPARAM_st;
      TPBEPARAM_st = record
          salt : PASN1_OCTET_STRING;
          iter : PASN1_INTEGER;
        end;

      PPPBE2PARAM=^PPBE2PARAM;
      PPBE2PARAM= ^TPBE2PARAM_st;
      TPBE2PARAM_st = record
          keyfunc : PX509_ALGOR;
          encryption : PX509_ALGOR;
        end;

      PPPBKDF2PARAM=^PPBKDF2PARAM;
      PPBKDF2PARAM= ^TPBKDF2PARAM_st;
      TPBKDF2PARAM_st = record
          salt : PASN1_TYPE;
          iter : PASN1_INTEGER;
          keylength : PASN1_INTEGER;
          prf : PX509_ALGOR;
        end;

{$define HEADER_X509_VFY_H}    
{$define HEADER_LHASH_H}

      Plhash_node_st=^Tlhash_node_st;
      Tlhash_node_st=record
       data:Pointer;
       next:Plhash_node_st;
       hash:culong;
      end;
      TOPENSSL_LH_NODE=Tlhash_node_st;

      TOPENSSL_LH_COMPFUNC = function  (para1:pointer; para2:pointer):cint;cdecl;

      TOPENSSL_LH_HASHFUNC = function  (para1:pointer):culong;cdecl;

      TOPENSSL_LH_DOALL_FUNC = procedure (para1:pointer);cdecl;

      TOPENSSL_LH_DOALL_FUNCARG = procedure (para1:pointer; para2:pointer);cdecl;

      POPENSSL_LHASH=Pointer;

    const
      LH_LOAD_MULT = 256;      

function  OPENSSL_LH_error(lh:POPENSSL_LHASH):cint;cdecl; external DLLUtilName;
function  OPENSSL_LH_new(h:TOPENSSL_LH_HASHFUNC; c:TOPENSSL_LH_COMPFUNC):POPENSSL_LHASH;cdecl; external DLLUtilName;
procedure OPENSSL_LH_free(lh:POPENSSL_LHASH);cdecl; external DLLUtilName;
function  OPENSSL_LH_insert(lh:POPENSSL_LHASH; data:pointer):pointer;cdecl; external DLLUtilName;
function  OPENSSL_LH_delete(lh:POPENSSL_LHASH; data:pointer):pointer;cdecl; external DLLUtilName;
function  OPENSSL_LH_retrieve(lh:POPENSSL_LHASH; data:pointer):pointer;cdecl; external DLLUtilName;
procedure OPENSSL_LH_doall(lh:POPENSSL_LHASH; func:TOPENSSL_LH_DOALL_FUNC);cdecl; external DLLUtilName;
procedure OPENSSL_LH_doall_arg(lh:POPENSSL_LHASH; func:TOPENSSL_LH_DOALL_FUNCARG; arg:pointer);cdecl; external DLLUtilName;
function  OPENSSL_LH_strhash(c:pbyte):culong;cdecl; external DLLUtilName;
function  OPENSSL_LH_num_items(lh:POPENSSL_LHASH):culong;cdecl; external DLLUtilName;
function  OPENSSL_LH_get_down_load(lh:POPENSSL_LHASH):culong;cdecl; external DLLUtilName;
procedure OPENSSL_LH_set_down_load(lh:POPENSSL_LHASH; down_load:culong);cdecl; external DLLUtilName;
//procedure OPENSSL_LH_stats(lh:POPENSSL_LHASH; fp:PFILE);cdecl; external DLLUtilName;
//procedure OPENSSL_LH_node_stats(lh:POPENSSL_LHASH; fp:PFILE);cdecl; external DLLUtilName;
//procedure OPENSSL_LH_node_usage_stats(lh:POPENSSL_LHASH; fp:PFILE);cdecl; external DLLUtilName;
procedure OPENSSL_LH_stats_bio(lh:POPENSSL_LHASH;_out:PBIO);cdecl; external DLLUtilName;
procedure OPENSSL_LH_node_stats_bio(lh:POPENSSL_LHASH;_out:PBIO);cdecl; external DLLUtilName;
procedure OPENSSL_LH_node_usage_stats_bio(lh:POPENSSL_LHASH;_out:PBIO);cdecl; external DLLUtilName;

    function  IMPLEMENT_LHASH_DOALL_ARG(_type,argtype : longint) : longint; cdecl; external DLLUtilName;

    type
      Plhash_st_OPENSSL_STRING = ^Tlhash_st_OPENSSL_STRING;
      Tlhash_st_OPENSSL_STRING = record
          dummy : record
              case longint of
                0 : ( d1 : pointer );
                1 : ( d2 : culong );
                2 : ( d3 : cint );
              end;
        end;

      Plhash_st_OPENSSL_CSTRING = ^Tlhash_st_OPENSSL_CSTRING;
      Tlhash_st_OPENSSL_CSTRING = record
          dummy : record
              case longint of
                0 : ( d1 : pointer );
                1 : ( d2 : culong );
                2 : ( d3 : cint );
              end;
        end;


      PX509_LOOKUP_TYPE = ^TX509_LOOKUP_TYPE;
      TX509_LOOKUP_TYPE =  Longint;
      Const
        X509_LU_NONE = 0;
        X509_LU_X509 = 1;
        X509_LU_CRL = 2;

      X509_LU_RETRY = -(1);      
      X509_LU_FAIL = 0;

    type
      Pstack_st_X509_LOOKUP = ^Tstack_st_X509_LOOKUP;
      Tstack_st_X509_LOOKUP = record
          {undefined structure}
        end;
      PX509_LOOKUP=Pstack_st_X509_LOOKUP;
      PPX509_LOOKUP=^PX509_LOOKUP;

      PX509_OBJECT=Pointer;
      PPX509_OBJECT=^PX509_OBJECT;

      PX509_STORE_CTX=Pointer;
      PX509_STORE=Pointer;

      Tsk_X509_LOOKUP_compfunc = function  (a:PPX509_LOOKUP; b:PPX509_LOOKUP):cint;cdecl;

      Tsk_X509_LOOKUP_freefunc = procedure (a:PX509_LOOKUP);cdecl;

      Tsk_X509_LOOKUP_copyfunc = function  (a:PX509_LOOKUP):PX509_LOOKUP;cdecl;

      Tsk_X509_OBJECT_compfunc = function  (a:PPX509_OBJECT; b:PPX509_OBJECT):cint;cdecl;

      Tsk_X509_OBJECT_freefunc = procedure (a:PX509_OBJECT);cdecl;

      Tsk_X509_OBJECT_copyfunc = function  (a:PX509_OBJECT):PX509_OBJECT;cdecl;

      Tsk_X509_VERIFY_PARAM_compfunc = function  (a:PPX509_VERIFY_PARAM; b:PPX509_VERIFY_PARAM):cint;cdecl;

      Tsk_X509_VERIFY_PARAM_freefunc = procedure (a:PX509_VERIFY_PARAM);cdecl;

      Tsk_X509_VERIFY_PARAM_copyfunc = function  (a:PX509_VERIFY_PARAM):PX509_VERIFY_PARAM;cdecl;

      TX509_STORE_CTX_verify_cb = function  (para1:cint; para2:PX509_STORE_CTX):cint;cdecl;

      TX509_STORE_CTX_verify_fn = function  (para1:PX509_STORE_CTX):cint;cdecl;

      TX509_STORE_CTX_get_issuer_fn = function  (issuer:PPX509; ctx:PX509_STORE_CTX; x:PX509):cint;cdecl;

      TX509_STORE_CTX_check_issued_fn = function  (ctx:PX509_STORE_CTX; x:PX509; issuer:PX509):cint;cdecl;

      TX509_STORE_CTX_check_revocation_fn = function  (ctx:PX509_STORE_CTX):cint;cdecl;

      TX509_STORE_CTX_get_crl_fn = function  (ctx:PX509_STORE_CTX; crl:PPX509_CRL; x:PX509):cint;cdecl;

      TX509_STORE_CTX_check_crl_fn = function  (ctx:PX509_STORE_CTX; crl:PX509_CRL):cint;cdecl;

      TX509_STORE_CTX_cert_crl_fn = function  (ctx:PX509_STORE_CTX; crl:PX509_CRL; x:PX509):cint;cdecl;

      TX509_STORE_CTX_check_policy_fn = function  (ctx:PX509_STORE_CTX):cint;cdecl;

      TX509_STORE_CTX_lookup_certs_fn = function  (ctx:PX509_STORE_CTX; nm:PX509_NAME):Pstack_st_X509;cdecl;

      TX509_STORE_CTX_lookup_crls_fn = function  (ctx:PX509_STORE_CTX; nm:PX509_NAME):Pstack_st_X509_CRL;cdecl;

      TX509_STORE_CTX_cleanup_fn = function  (ctx:PX509_STORE_CTX):cint;cdecl;

procedure X509_STORE_CTX_set_depth(ctx:PX509_STORE_CTX; depth:cint);cdecl; external DLLUtilName;

    function  X509_STORE_CTX_set_app_data(ctx:PX509_STORE_CTX;data : pointer) : cint;

    function  X509_STORE_CTX_get_app_data(ctx : PX509_STORE_CTX) : pointer;

    const
      X509_L_FILE_LOAD = 1;      
      X509_L_ADD_DIR = 2;      

    function  X509_LOOKUP_load_file(x:PX509_STORE_CTX;name:Pbyte;_type:clong) : cint;

    function  X509_LOOKUP_add_dir(x:PX509_STORE_CTX;name:Pbyte;_type:clong) : cint;

    const
      X509_V_OK = 0;      
      X509_V_ERR_UNSPECIFIED = 1;      
      X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2;      
      X509_V_ERR_UNABLE_TO_GET_CRL = 3;      
      X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4;      
      X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5;      
      X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6;      
      X509_V_ERR_CERT_SIGNATURE_FAILURE = 7;      
      X509_V_ERR_CRL_SIGNATURE_FAILURE = 8;      
      X509_V_ERR_CERT_NOT_YET_VALID = 9;      
      X509_V_ERR_CERT_HAS_EXPIRED = 10;      
      X509_V_ERR_CRL_NOT_YET_VALID = 11;      
      X509_V_ERR_CRL_HAS_EXPIRED = 12;      
      X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13;      
      X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14;      
      X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15;      
      X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16;      
      X509_V_ERR_OUT_OF_MEM = 17;      
      X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;      
      X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;      
      X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;      
      X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;      
      X509_V_ERR_CERT_CHAIN_TOO_LONG = 22;      
      X509_V_ERR_CERT_REVOKED = 23;      
      X509_V_ERR_INVALID_CA = 24;      
      X509_V_ERR_PATH_LENGTH_EXCEEDED = 25;      
      X509_V_ERR_INVALID_PURPOSE = 26;      
      X509_V_ERR_CERT_UNTRUSTED = 27;      
      X509_V_ERR_CERT_REJECTED = 28;      
      X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29;      
      X509_V_ERR_AKID_SKID_MISMATCH = 30;      
      X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;      
      X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32;      
      X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33;      
      X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34;      
      X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35;      
      X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36;      
      X509_V_ERR_INVALID_NON_CA = 37;      
      X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38;      
      X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39;      
      X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40;      
      X509_V_ERR_INVALID_EXTENSION = 41;      
      X509_V_ERR_INVALID_POLICY_EXTENSION = 42;      
      X509_V_ERR_NO_EXPLICIT_POLICY = 43;      
      X509_V_ERR_DIFFERENT_CRL_SCOPE = 44;      
      X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = 45;      
      X509_V_ERR_UNNESTED_RESOURCE = 46;      
      X509_V_ERR_PERMITTED_VIOLATION = 47;      
      X509_V_ERR_EXCLUDED_VIOLATION = 48;      
      X509_V_ERR_SUBTREE_MINMAX = 49;      
      X509_V_ERR_APPLICATION_VERIFICATION = 50;      
      X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = 51;      
      X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 52;      
      X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = 53;      
      X509_V_ERR_CRL_PATH_VALIDATION_ERROR = 54;      
      X509_V_ERR_PATH_LOOP = 55;      
      X509_V_ERR_SUITE_B_INVALID_VERSION = 56;      
      X509_V_ERR_SUITE_B_INVALID_ALGORITHM = 57;      
      X509_V_ERR_SUITE_B_INVALID_CURVE = 58;      
      X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM = 59;      
      X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED = 60;      
      X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = 61;      
      X509_V_ERR_HOSTNAME_MISMATCH = 62;      
      X509_V_ERR_EMAIL_MISMATCH = 63;      
      X509_V_ERR_IP_ADDRESS_MISMATCH = 64;      
      X509_V_ERR_DANE_NO_MATCH = 65;      
      X509_V_ERR_EE_KEY_TOO_SMALL = 66;      
      X509_V_ERR_CA_KEY_TOO_SMALL = 67;      
      X509_V_ERR_CA_MD_TOO_WEAK = 68;      
      X509_V_ERR_INVALID_CALL = 69;      
      X509_V_ERR_STORE_LOOKUP = 70;      
      X509_V_ERR_NO_VALID_SCTS = 71;      
      X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION = 72;      
      X509_V_FLAG_CB_ISSUER_CHECK = $0;      
      X509_V_FLAG_USE_CHECK_TIME = $2;      
      X509_V_FLAG_CRL_CHECK = $4;      
      X509_V_FLAG_CRL_CHECK_ALL = $8;      
      X509_V_FLAG_IGNORE_CRITICAL = $10;      
      X509_V_FLAG_X509_STRICT = $20;      
      X509_V_FLAG_ALLOW_PROXY_CERTS = $40;      
      X509_V_FLAG_POLICY_CHECK = $80;      
      X509_V_FLAG_EXPLICIT_POLICY = $100;      
      X509_V_FLAG_INHIBIT_ANY = $200;      
      X509_V_FLAG_INHIBIT_MAP = $400;      
      X509_V_FLAG_NOTIFY_POLICY = $800;      
      X509_V_FLAG_EXTENDED_CRL_SUPPORT = $1000;      
      X509_V_FLAG_USE_DELTAS = $2000;      
      X509_V_FLAG_CHECK_SS_SIGNATURE = $4000;      
      X509_V_FLAG_TRUSTED_FIRST = $8000;      
      X509_V_FLAG_SUITEB_128_LOS_ONLY = $10000;      
      X509_V_FLAG_SUITEB_192_LOS = $20000;      
      X509_V_FLAG_SUITEB_128_LOS = $30000;      
      X509_V_FLAG_PARTIAL_CHAIN = $80000;      
      X509_V_FLAG_NO_ALT_CHAINS = $100000;      
      X509_V_FLAG_NO_CHECK_TIME = $200000;      
      X509_VP_FLAG_DEFAULT = $1;      
      X509_VP_FLAG_OVERWRITE = $2;      
      X509_VP_FLAG_RESET_FLAGS = $4;      
      X509_VP_FLAG_LOCKED = $8;      
      X509_VP_FLAG_ONCE = $10;      
      X509_V_FLAG_POLICY_MASK = ((X509_V_FLAG_POLICY_CHECK or X509_V_FLAG_EXPLICIT_POLICY) or X509_V_FLAG_INHIBIT_ANY) or X509_V_FLAG_INHIBIT_MAP;      

function  X509_OBJECT_idx_by_subject(h:PX509_OBJECT; _type:TX509_LOOKUP_TYPE; name:PX509_NAME):cint;cdecl; external DLLUtilName;
function  X509_OBJECT_retrieve_by_subject(h:PX509_OBJECT; _type:TX509_LOOKUP_TYPE; name:PX509_NAME):PX509_OBJECT;cdecl; external DLLUtilName;
function  X509_OBJECT_retrieve_match(h:PX509_OBJECT; x:PX509_OBJECT):PX509_OBJECT;cdecl; external DLLUtilName;
function  X509_OBJECT_up_ref_count(a:PX509_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_OBJECT_new:PX509_OBJECT;cdecl; external DLLUtilName;
procedure X509_OBJECT_free(a:PX509_OBJECT);cdecl; external DLLUtilName;
function  X509_OBJECT_get_type(a:PX509_OBJECT):TX509_LOOKUP_TYPE;cdecl; external DLLUtilName;
function  X509_OBJECT_get0_X509(a:PX509_OBJECT):PX509;cdecl; external DLLUtilName;
function  X509_OBJECT_get0_X509_CRL(a:PX509_OBJECT):PX509_CRL;cdecl; external DLLUtilName;
function  X509_STORE_new:PX509_STORE;cdecl; external DLLUtilName;
procedure X509_STORE_free(v:PX509_STORE);cdecl; external DLLUtilName;
function  X509_STORE_lock(ctx:PX509_STORE):cint;cdecl; external DLLUtilName;
function  X509_STORE_unlock(ctx:PX509_STORE):cint;cdecl; external DLLUtilName;
function  X509_STORE_up_ref(v:PX509_STORE):cint;cdecl; external DLLUtilName;
function  X509_STORE_set_flags(ctx:PX509_STORE; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_STORE_set_purpose(ctx:PX509_STORE; purpose:cint):cint;cdecl; external DLLUtilName;
function  X509_STORE_set_trust(ctx:PX509_STORE; trust:cint):cint;cdecl; external DLLUtilName;
function  X509_STORE_set1_param(ctx:PX509_STORE; pm:PX509_VERIFY_PARAM):cint;cdecl; external DLLUtilName;
function  X509_STORE_get0_param(ctx:PX509_STORE):PX509_VERIFY_PARAM;cdecl; external DLLUtilName;
procedure X509_STORE_set_verify(ctx:PX509_STORE; verify:TX509_STORE_CTX_verify_fn);cdecl; external DLLUtilName;

    Procedure  X509_STORE_set_verify_func(ctx:PX509_STORE; func : TX509_STORE_CTX_verify_fn);

procedure X509_STORE_CTX_set_verify(ctx:PX509_STORE_CTX; verify:TX509_STORE_CTX_verify_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_verify(ctx:PX509_STORE):TX509_STORE_CTX_verify_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_verify_cb(ctx:PX509_STORE; verify_cb:TX509_STORE_CTX_verify_cb);cdecl; external DLLUtilName;

    procedure  X509_STORE_set_verify_cb_func(ctx:PX509_STORE;func:TX509_STORE_CTX_verify_cb);

function  X509_STORE_get_verify_cb(ctx:PX509_STORE):TX509_STORE_CTX_verify_cb;cdecl; external DLLUtilName;
procedure X509_STORE_set_get_issuer(ctx:PX509_STORE; get_issuer:TX509_STORE_CTX_get_issuer_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_get_issuer(ctx:PX509_STORE):TX509_STORE_CTX_get_issuer_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_check_issued(ctx:PX509_STORE; check_issued:TX509_STORE_CTX_check_issued_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_check_issued(ctx:PX509_STORE):TX509_STORE_CTX_check_issued_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_check_revocation(ctx:PX509_STORE; check_revocation:TX509_STORE_CTX_check_revocation_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_check_revocation(ctx:PX509_STORE):TX509_STORE_CTX_check_revocation_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_get_crl(ctx:PX509_STORE; get_crl:TX509_STORE_CTX_get_crl_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_get_crl(ctx:PX509_STORE):TX509_STORE_CTX_get_crl_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_check_crl(ctx:PX509_STORE; check_crl:TX509_STORE_CTX_check_crl_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_check_crl(ctx:PX509_STORE):TX509_STORE_CTX_check_crl_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_cert_crl(ctx:PX509_STORE; cert_crl:TX509_STORE_CTX_cert_crl_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_cert_crl(ctx:PX509_STORE):TX509_STORE_CTX_cert_crl_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_check_policy(ctx:PX509_STORE; check_policy:TX509_STORE_CTX_check_policy_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_check_policy(ctx:PX509_STORE):TX509_STORE_CTX_check_policy_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_lookup_certs(ctx:PX509_STORE; lookup_certs:TX509_STORE_CTX_lookup_certs_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_lookup_certs(ctx:PX509_STORE):TX509_STORE_CTX_lookup_certs_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_lookup_crls(ctx:PX509_STORE; lookup_crls:TX509_STORE_CTX_lookup_crls_fn);cdecl; external DLLUtilName;

    procedure  X509_STORE_set_lookup_crls_cb(ctx:PX509_STORE;func:TX509_STORE_CTX_lookup_crls_fn);

function  X509_STORE_get_lookup_crls(ctx:PX509_STORE):TX509_STORE_CTX_lookup_crls_fn;cdecl; external DLLUtilName;
procedure X509_STORE_set_cleanup(ctx:PX509_STORE; cleanup:TX509_STORE_CTX_cleanup_fn);cdecl; external DLLUtilName;
function  X509_STORE_get_cleanup(ctx:PX509_STORE):TX509_STORE_CTX_cleanup_fn;cdecl; external DLLUtilName;

    function  X509_STORE_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  X509_STORE_set_ex_data(ctx:PX509_STORE; idx:cint; data:pointer):cint;cdecl; external DLLUtilName;
function  X509_STORE_get_ex_data(ctx:PX509_STORE; idx:cint):pointer;cdecl; external DLLUtilName;
function  X509_STORE_CTX_new:PX509_STORE_CTX;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get1_issuer(issuer:PPX509; ctx:PX509_STORE_CTX; x:PX509):cint;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_free(ctx:PX509_STORE_CTX);cdecl; external DLLUtilName;
function  X509_STORE_CTX_init(ctx:PX509_STORE_CTX; store:PX509_STORE; x509:PX509; chain:Pstack_st_X509):cint;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set0_trusted_stack(ctx:PX509_STORE_CTX; sk:Pstack_st_X509);cdecl; external DLLUtilName;
procedure X509_STORE_CTX_cleanup(ctx:PX509_STORE_CTX);cdecl; external DLLUtilName;
function  X509_STORE_CTX_get0_store(ctx:PX509_STORE_CTX):PX509_STORE;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get0_cert(ctx:PX509_STORE_CTX):PX509;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set0_untrusted(ctx:PX509_STORE_CTX; sk:Pstack_st_X509);cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set_verify_cb(ctx:PX509_STORE_CTX; verify:TX509_STORE_CTX_verify_cb);cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_verify_cb(ctx:PX509_STORE_CTX):TX509_STORE_CTX_verify_cb;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_verify(ctx:PX509_STORE_CTX):TX509_STORE_CTX_verify_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_get_issuer(ctx:PX509_STORE_CTX):TX509_STORE_CTX_get_issuer_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_check_issued(ctx:PX509_STORE_CTX):TX509_STORE_CTX_check_issued_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_check_revocation(ctx:PX509_STORE_CTX):TX509_STORE_CTX_check_revocation_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_get_crl(ctx:PX509_STORE_CTX):TX509_STORE_CTX_get_crl_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_check_crl(ctx:PX509_STORE_CTX):TX509_STORE_CTX_check_crl_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_cert_crl(ctx:PX509_STORE_CTX):TX509_STORE_CTX_cert_crl_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_check_policy(ctx:PX509_STORE_CTX):TX509_STORE_CTX_check_policy_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_lookup_certs(ctx:PX509_STORE_CTX):TX509_STORE_CTX_lookup_certs_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_lookup_crls(ctx:PX509_STORE_CTX):TX509_STORE_CTX_lookup_crls_fn;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_cleanup(ctx:PX509_STORE_CTX):TX509_STORE_CTX_cleanup_fn;cdecl; external DLLUtilName;

function  X509_STORE_add_lookup(v:PX509_STORE; m:PX509_LOOKUP_METHOD):PX509_LOOKUP;cdecl; external DLLUtilName;
function  X509_LOOKUP_hash_dir:PX509_LOOKUP_METHOD;cdecl; external DLLUtilName;
function  X509_LOOKUP_file:PX509_LOOKUP_METHOD;cdecl; external DLLUtilName;
function  X509_STORE_add_cert(ctx:PX509_STORE; x:PX509):cint;cdecl; external DLLUtilName;
function  X509_STORE_add_crl(ctx:PX509_STORE; x:PX509_CRL):cint;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_by_subject(vs:PX509_STORE_CTX; _type:TX509_LOOKUP_TYPE; name:PX509_NAME; ret:PX509_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_obj_by_subject(vs:PX509_STORE_CTX; _type:TX509_LOOKUP_TYPE; name:PX509_NAME):PX509_OBJECT;cdecl; external DLLUtilName;
function  X509_LOOKUP_ctrl(ctx:PX509_LOOKUP; cmd:cint; argc:pbyte; argl:clong; ret:Ppbyte):cint;cdecl; external DLLUtilName;
function  X509_load_cert_file(ctx:PX509_LOOKUP; _file:pbyte; _type:cint):cint;cdecl; external DLLUtilName;
function  X509_load_crl_file(ctx:PX509_LOOKUP; _file:pbyte; _type:cint):cint;cdecl; external DLLUtilName;
function  X509_load_cert_crl_file(ctx:PX509_LOOKUP; _file:pbyte; _type:cint):cint;cdecl; external DLLUtilName;
function  X509_LOOKUP_new(method:PX509_LOOKUP_METHOD):PX509_LOOKUP;cdecl; external DLLUtilName;
procedure X509_LOOKUP_free(ctx:PX509_LOOKUP);cdecl; external DLLUtilName;
function  X509_LOOKUP_init(ctx:PX509_LOOKUP):cint;cdecl; external DLLUtilName;
function  X509_LOOKUP_by_subject(ctx:PX509_LOOKUP; _type:TX509_LOOKUP_TYPE; name:PX509_NAME; ret:PX509_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_LOOKUP_by_issuer_serial(ctx:PX509_LOOKUP; _type:TX509_LOOKUP_TYPE; name:PX509_NAME; serial:PASN1_INTEGER; ret:PX509_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_LOOKUP_by_fingerprint(ctx:PX509_LOOKUP; _type:TX509_LOOKUP_TYPE; bytes:pbyte; len:cint; ret:PX509_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_LOOKUP_by_alias(ctx:PX509_LOOKUP; _type:TX509_LOOKUP_TYPE; str:pbyte; len:cint; ret:PX509_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_LOOKUP_shutdown(ctx:PX509_LOOKUP):cint;cdecl; external DLLUtilName;
function  X509_STORE_load_locations(ctx:PX509_STORE; _file:pbyte; dir:pbyte):cint;cdecl; external DLLUtilName;
function  X509_STORE_set_default_paths(ctx:PX509_STORE):cint;cdecl; external DLLUtilName;

    function  X509_STORE_CTX_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  X509_STORE_CTX_set_ex_data(ctx:PX509_STORE_CTX; idx:cint; data:pointer):cint;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_ex_data(ctx:PX509_STORE_CTX; idx:cint):pointer;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_error(ctx:PX509_STORE_CTX):cint;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set_error(ctx:PX509_STORE_CTX; s:cint);cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_error_depth(ctx:PX509_STORE_CTX):cint;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set_error_depth(ctx:PX509_STORE_CTX; depth:cint);cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_current_cert(ctx:PX509_STORE_CTX):PX509;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set_current_cert(ctx:PX509_STORE_CTX; x:PX509);cdecl; external DLLUtilName;
function  X509_STORE_CTX_get0_current_issuer(ctx:PX509_STORE_CTX):PX509;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get0_current_crl(ctx:PX509_STORE_CTX):PX509_CRL;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get0_parent_ctx(ctx:PX509_STORE_CTX):PX509_STORE_CTX;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set_cert(c:PX509_STORE_CTX; x:PX509);cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set0_verified_chain(c:PX509_STORE_CTX; sk:Pstack_st_X509);cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set0_crls(c:PX509_STORE_CTX; sk:Pstack_st_X509_CRL);cdecl; external DLLUtilName;
function  X509_STORE_CTX_set_purpose(ctx:PX509_STORE_CTX; purpose:cint):cint;cdecl; external DLLUtilName;
function  X509_STORE_CTX_set_trust(ctx:PX509_STORE_CTX; trust:cint):cint;cdecl; external DLLUtilName;
function  X509_STORE_CTX_purpose_inherit(ctx:PX509_STORE_CTX; def_purpose:cint; purpose:cint; trust:cint):cint;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set_flags(ctx:PX509_STORE_CTX; flags:culong);cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set_time(ctx:PX509_STORE_CTX; flags:culong; t:time_t);cdecl; external DLLUtilName;
function  X509_STORE_CTX_get0_policy_tree(ctx:PX509_STORE_CTX):PX509_POLICY_TREE;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_explicit_policy(ctx:PX509_STORE_CTX):cint;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get_num_untrusted(ctx:PX509_STORE_CTX):cint;cdecl; external DLLUtilName;
function  X509_STORE_CTX_get0_param(ctx:PX509_STORE_CTX):PX509_VERIFY_PARAM;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set0_param(ctx:PX509_STORE_CTX; param:PX509_VERIFY_PARAM);cdecl; external DLLUtilName;
function  X509_STORE_CTX_set_default(ctx:PX509_STORE_CTX; name:pbyte):cint;cdecl; external DLLUtilName;
procedure X509_STORE_CTX_set0_dane(ctx:PX509_STORE_CTX; dane:PSSL_DANE);cdecl; external DLLUtilName;

    const
      DANE_FLAG_NO_DANE_EE_NAMECHECKS = 1 shl 0;      

function  X509_VERIFY_PARAM_new:PX509_VERIFY_PARAM;cdecl; external DLLUtilName;
procedure X509_VERIFY_PARAM_free(param:PX509_VERIFY_PARAM);cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_inherit(_to:PX509_VERIFY_PARAM; from:PX509_VERIFY_PARAM):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set1(_to:PX509_VERIFY_PARAM; from:PX509_VERIFY_PARAM):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set1_name(param:PX509_VERIFY_PARAM; name:pbyte):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set_flags(param:PX509_VERIFY_PARAM; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_clear_flags(param:PX509_VERIFY_PARAM; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get_flags(param:PX509_VERIFY_PARAM):culong;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set_purpose(param:PX509_VERIFY_PARAM; purpose:cint):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set_trust(param:PX509_VERIFY_PARAM; trust:cint):cint;cdecl; external DLLUtilName;
procedure X509_VERIFY_PARAM_set_depth(param:PX509_VERIFY_PARAM; depth:cint);cdecl; external DLLUtilName;
procedure X509_VERIFY_PARAM_set_auth_level(param:PX509_VERIFY_PARAM; auth_level:cint);cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get_time(param:PX509_VERIFY_PARAM):time_t;cdecl; external DLLUtilName;
procedure X509_VERIFY_PARAM_set_time(param:PX509_VERIFY_PARAM; t:time_t);cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_add0_policy(param:PX509_VERIFY_PARAM; policy:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set1_policies(param:PX509_VERIFY_PARAM; policies:Pstack_st_ASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set_inh_flags(param:PX509_VERIFY_PARAM; flags:uint32):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get_inh_flags(param:PX509_VERIFY_PARAM):uint32;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set1_host(param:PX509_VERIFY_PARAM; name:pbyte; namelen:size_t):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_add1_host(param:PX509_VERIFY_PARAM; name:pbyte; namelen:size_t):cint;cdecl; external DLLUtilName;
procedure X509_VERIFY_PARAM_set_hostflags(param:PX509_VERIFY_PARAM; flags:cuint);cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get0_peername(para1:PX509_VERIFY_PARAM):pbyte;cdecl; external DLLUtilName;
procedure X509_VERIFY_PARAM_move_peername(para1:PX509_VERIFY_PARAM; para2:PX509_VERIFY_PARAM);cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set1_email(param:PX509_VERIFY_PARAM; email:pbyte; emaillen:size_t):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set1_ip(param:PX509_VERIFY_PARAM; ip:pbyte; iplen:size_t):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_set1_ip_asc(param:PX509_VERIFY_PARAM; ipasc:pbyte):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get_depth(param:PX509_VERIFY_PARAM):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get_auth_level(param:PX509_VERIFY_PARAM):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get0_name(param:PX509_VERIFY_PARAM):pbyte;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_add0_table(param:PX509_VERIFY_PARAM):cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get_count:cint;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_get0(id:cint):PX509_VERIFY_PARAM;cdecl; external DLLUtilName;
function  X509_VERIFY_PARAM_lookup(name:pbyte):PX509_VERIFY_PARAM;cdecl; external DLLUtilName;
procedure X509_VERIFY_PARAM_table_cleanup;cdecl; external DLLUtilName;

    const
      X509_PCY_TREE_FAILURE = -(2);      
      X509_PCY_TREE_INVALID = -(1);      
      X509_PCY_TREE_INTERNAL = 0;      
      X509_PCY_TREE_VALID = 1;      
      X509_PCY_TREE_EMPTY = 2;      
      X509_PCY_TREE_EXPLICIT = 4;      

function  X509_policy_check(ptree:PPX509_POLICY_TREE; pexplicit_policy:pcint; certs:Pstack_st_X509; policy_oids:Pstack_st_ASN1_OBJECT; flags:cuint):cint;cdecl; external DLLUtilName;
procedure X509_policy_tree_free(tree:PX509_POLICY_TREE);cdecl; external DLLUtilName;
function  X509_policy_tree_level_count(tree:PX509_POLICY_TREE):cint;cdecl; external DLLUtilName;
function  X509_policy_tree_get0_level(tree:PX509_POLICY_TREE; i:cint):PX509_POLICY_LEVEL;cdecl; external DLLUtilName;
function  X509_policy_level_node_count(level:PX509_POLICY_LEVEL):cint;cdecl; external DLLUtilName;
function  X509_policy_level_get0_node(level:PX509_POLICY_LEVEL; i:cint):PX509_POLICY_NODE;cdecl; external DLLUtilName;
function  X509_policy_node_get0_policy(node:PX509_POLICY_NODE):PASN1_OBJECT;cdecl; external DLLUtilName;
function  X509_policy_node_get0_parent(node:PX509_POLICY_NODE):PX509_POLICY_NODE;cdecl; external DLLUtilName;
{$define HEADER_PKCS7_H}    
    type
      PPPKCS7_ISSUER_AND_SERIAL=^PPKCS7_ISSUER_AND_SERIAL;
      Ppkcs7_issuer_and_serial= ^Tpkcs7_issuer_and_serial_st;
      Tpkcs7_issuer_and_serial_st = record
          issuer : PX509_NAME;
          serial : PASN1_INTEGER;
        end;

      Ppkcs7_signer_info= ^Tpkcs7_signer_info_st;
      Tpkcs7_signer_info_st = record
          version : PASN1_INTEGER;
          issuer_and_serial : PPKCS7_ISSUER_AND_SERIAL;
          digest_alg : PX509_ALGOR;
          auth_attr : Pstack_st_X509_ATTRIBUTE;
          digest_enc_alg : PX509_ALGOR;
          enc_digest : PASN1_OCTET_STRING;
          unauth_attr : Pstack_st_X509_ATTRIBUTE;
          pkey : PEVP_PKEY;
        end;
      PPPKCS7_SIGNER_INFO=PPKCS7_SIGNER_INFO;

      Pstack_st_PKCS7_SIGNER_INFO = ^Tstack_st_PKCS7_SIGNER_INFO;
      Tstack_st_PKCS7_SIGNER_INFO = record
          {undefined structure}
        end;


      Tsk_PKCS7_SIGNER_INFO_compfunc = function  (a:PPPKCS7_SIGNER_INFO; b:PPPKCS7_SIGNER_INFO):cint;cdecl;

      Tsk_PKCS7_SIGNER_INFO_freefunc = procedure (a:PPKCS7_SIGNER_INFO);cdecl;

      Tsk_PKCS7_SIGNER_INFO_copyfunc = function  (a:PPKCS7_SIGNER_INFO):PPKCS7_SIGNER_INFO;cdecl;

    type
      Pstack_st_PKCS7_RECIP_INFO = ^Tstack_st_PKCS7_RECIP_INFO;
      Tstack_st_PKCS7_RECIP_INFO = record
          {undefined structure}
        end;
      PPKCS7_RECIP_INFO=Pstack_st_PKCS7_RECIP_INFO;
      PPPKCS7_RECIP_INFO=^PPKCS7_RECIP_INFO;

      Tsk_PKCS7_RECIP_INFO_compfunc = function  (a:PPPKCS7_RECIP_INFO; b:PPPKCS7_RECIP_INFO):cint;cdecl;

      Tsk_PKCS7_RECIP_INFO_freefunc = procedure (a:PPKCS7_RECIP_INFO);cdecl;

      Tsk_PKCS7_RECIP_INFO_copyfunc = function  (a:PPKCS7_RECIP_INFO):PPKCS7_RECIP_INFO;cdecl;

      PPPKCS7_ENC_CONTENT=^PPKCS7_ENC_CONTENT;
      Ppkcs7_enc_content= ^Tpkcs7_enc_content_st;
      Tpkcs7_enc_content_st = record
          content_type : PASN1_OBJECT;
          algorithm : PX509_ALGOR;
          enc_data : PASN1_OCTET_STRING;
          cipher : PEVP_CIPHER;
        end;

      Ppkcs7_enveloped= ^Tpkcs7_enveloped_st;
      Tpkcs7_enveloped_st = record
          version : PASN1_INTEGER;
          recipientinfo : Pstack_st_PKCS7_RECIP_INFO;
          enc_data : PPKCS7_ENC_CONTENT;
        end;
      TPKCS7_ENVELOPE = Tpkcs7_enveloped_st;
      PPKCS7_ENVELOPE = ^TPKCS7_ENVELOPE;
      PPPKCS7_ENVELOPE=^PPKCS7_ENVELOPE;

      Ppkcs7_signedandenveloped= ^Tpkcs7_signedandenveloped_st;
      Tpkcs7_signedandenveloped_st = record
          version : PASN1_INTEGER;
          md_algs : Pstack_st_X509_ALGOR;
          cert : Pstack_st_X509;
          crl : Pstack_st_X509_CRL;
          signer_info : Pstack_st_PKCS7_SIGNER_INFO;
          enc_data : PPKCS7_ENC_CONTENT;
          recipientinfo : Pstack_st_PKCS7_RECIP_INFO;
        end;
      TPKCS7_SIGN_ENVELOPE = Tpkcs7_signedandenveloped_st;
      PPKCS7_SIGN_ENVELOPE = ^TPKCS7_SIGN_ENVELOPE;
      PPPKCS7_SIGN_ENVELOPE=^PPKCS7_SIGN_ENVELOPE;

      PPPKCS7=^PPKCS7;
      Ppkcs7= ^Tpkcs7_st;

      PPPKCS7_DIGEST=^PPKCS7_DIGEST;
      Ppkcs7_digest= ^Tpkcs7_digest_st;
      Tpkcs7_digest_st = record
          version : PASN1_INTEGER;
          md : PX509_ALGOR;
          contents : Ppkcs7;
          digest : PASN1_OCTET_STRING;
        end;

      Ppkcs7_encrypted= ^Tpkcs7_encrypted_st;
      Tpkcs7_encrypted_st = record
          version : PASN1_INTEGER;
          enc_data : PPKCS7_ENC_CONTENT;
        end;
      TPKCS7_ENCRYPT = Tpkcs7_encrypted_st;
      PPKCS7_ENCRYPT = ^TPKCS7_ENCRYPT;
      PPPKCS7_ENCRYPT=^PPKCS7_ENCRYPT;

      Tpkcs7_st = record
       {
       * The following is non NULL if it contains ASN1 encoding of this
       * structure
       }
       asn1:PByte;
       length:clong;
       state:cint;                  // used during processing
       detached:cint;
       _type:PASN1_OBJECT;
        { content as defined by the type
         * all encryption/message digests are applied to the 'contents', leaving
         * out the 'type' field.
         }
       d:record
        Case Byte of
         0:(ptr:PByte);
         // NID_pkcs7_data
         1:(data:PASN1_OCTET_STRING);
         // NID_pkcs7_signed
         2:(sign:PPKCS7_SIGNED);
         // NID_pkcs7_enveloped
         3:(enveloped:PPKCS7_ENVELOPE);
         // NID_pkcs7_signedAndEnveloped
         4:(signed_and_enveloped:PPKCS7_SIGN_ENVELOPE);
         // NID_pkcs7_digest
         5:(digest:PPKCS7_DIGEST);
         // NID_pkcs7_encrypted
         6:(encrypted:PPKCS7_ENCRYPT);
         // Anything else
         7:(other:PASN1_TYPE);
       end;
      end;


      Pstack_st_PKCS7 = ^Tstack_st_PKCS7;
      Tstack_st_PKCS7 = record
          {undefined structure}
        end;


      Tsk_PKCS7_compfunc = function  (a:PPPKCS7; b:PPPKCS7):cint;cdecl;

      Tsk_PKCS7_freefunc = procedure (a:PPKCS7);cdecl;

      Tsk_PKCS7_copyfunc = function  (a:PPKCS7):PPKCS7;cdecl;

    const
      PKCS7_S_HEADER  =0;
      PKCS7_S_BODY    =1;
      PKCS7_S_TAIL    =2;

      PKCS7_OP_SET_DETACHED_SIGNATURE=1;
      PKCS7_OP_GET_DETACHED_SIGNATURE=2;

    function  PKCS7_get_signed_attributes(si : Ppkcs7_signer_info) : PX509_ATTRIBUTE;

    function  PKCS7_get_attributes(si : Ppkcs7_signer_info) : PX509_ATTRIBUTE;

    function  PKCS7_type_is_signed(a : Ppkcs7) : Boolean;

    function  PKCS7_type_is_encrypted(a : Ppkcs7) : Boolean;

    function  PKCS7_type_is_enveloped(a : Ppkcs7) : Boolean;

    function  PKCS7_type_is_signedAndEnveloped(a : Ppkcs7) : Boolean;

    function  PKCS7_type_is_data(a : Ppkcs7) : Boolean;

    function  PKCS7_type_is_digest(a : Ppkcs7) : Boolean;

    function  PKCS7_set_detached(p:Ppkcs7;v : clong) : clong;

    function  PKCS7_get_detached(p : Ppkcs7) : clong;

    function  PKCS7_is_detached(p7 : Ppkcs7) : Boolean;

    const
      _PKCS7_TEXT = $1;      
      _PKCS7_NOCERTS = $2;      
      _PKCS7_NOSIGS = $4;      
      _PKCS7_NOCHAIN = $8;      
      _PKCS7_NOINTERN = $10;      
      _PKCS7_NOVERIFY = $20;      
      _PKCS7_DETACHED = $40;      
      _PKCS7_BINARY = $80;      
      _PKCS7_NOATTR = $100;      
      _PKCS7_NOSMIMECAP = $200;      
      _PKCS7_NOOLDMIMETYPE = $400;      
      _PKCS7_CRLFEOL = $800;      
      _PKCS7_STREAM = $1000;      
      _PKCS7_NOCRL = $2000;      
      _PKCS7_PARTIAL = $4000;      
      _PKCS7_REUSE_DIGEST = $8000;      
      _PKCS7_NO_DUAL_CONTENT = $10000;      
      _SMIME_TEXT      = _PKCS7_TEXT;
      _SMIME_NOCERTS   = _PKCS7_NOCERTS;
      _SMIME_NOSIGS    = _PKCS7_NOSIGS;
      _SMIME_NOCHAIN   = _PKCS7_NOCHAIN;
      _SMIME_NOINTERN  = _PKCS7_NOINTERN;
      _SMIME_NOVERIFY  = _PKCS7_NOVERIFY;
      _SMIME_DETACHED  = _PKCS7_DETACHED;
      _SMIME_BINARY    = _PKCS7_BINARY;
      _SMIME_NOATTR    = _PKCS7_NOATTR;
      _SMIME_ASCIICRLF = $80000;      

function  PKCS7_ISSUER_AND_SERIAL_new:PPKCS7_ISSUER_AND_SERIAL;cdecl; external DLLUtilName;
procedure PKCS7_ISSUER_AND_SERIAL_free(a:PPKCS7_ISSUER_AND_SERIAL);cdecl; external DLLUtilName;
function  d2i_PKCS7_ISSUER_AND_SERIAL(a:PPPKCS7_ISSUER_AND_SERIAL;_in:Ppbyte; len:clong):PPKCS7_ISSUER_AND_SERIAL;cdecl; external DLLUtilName;
function  i2d_PKCS7_ISSUER_AND_SERIAL(a:PPKCS7_ISSUER_AND_SERIAL;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_ISSUER_AND_SERIAL_digest(data:PPKCS7_ISSUER_AND_SERIAL; _type:PEVP_MD; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
//function  d2i_PKCS7_fp(fp:PFILE; p7:PPPKCS7):PPKCS7;cdecl; external DLLUtilName;
//function  i2d_PKCS7_fp(fp:PFILE; p7:PPKCS7):cint;cdecl; external DLLUtilName;
function  PKCS7_dup(p7:PPKCS7):PPKCS7;cdecl; external DLLUtilName;
function  d2i_PKCS7_bio(bp:PBIO; p7:PPPKCS7):PPKCS7;cdecl; external DLLUtilName;
function  i2d_PKCS7_bio(bp:PBIO; p7:PPKCS7):cint;cdecl; external DLLUtilName;
function  i2d_PKCS7_bio_stream(_out:PBIO; p7:PPKCS7;_in:PBIO; flags:cint):cint;cdecl; external DLLUtilName;
function  PEM_write_bio_PKCS7_stream(_out:PBIO; p7:PPKCS7;_in:PBIO; flags:cint):cint;cdecl; external DLLUtilName;
function  PKCS7_SIGNER_INFO_new:PPKCS7_SIGNER_INFO;cdecl; external DLLUtilName;
procedure PKCS7_SIGNER_INFO_free(a:PPKCS7_SIGNER_INFO);cdecl; external DLLUtilName;
function  d2i_PKCS7_SIGNER_INFO(a:PPPKCS7_SIGNER_INFO;_in:Ppbyte; len:clong):PPKCS7_SIGNER_INFO;cdecl; external DLLUtilName;
function  i2d_PKCS7_SIGNER_INFO(a:PPKCS7_SIGNER_INFO;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_RECIP_INFO_new:PPKCS7_RECIP_INFO;cdecl; external DLLUtilName;
procedure PKCS7_RECIP_INFO_free(a:PPKCS7_RECIP_INFO);cdecl; external DLLUtilName;
function  d2i_PKCS7_RECIP_INFO(a:PPPKCS7_RECIP_INFO;_in:Ppbyte; len:clong):PPKCS7_RECIP_INFO;cdecl; external DLLUtilName;
function  i2d_PKCS7_RECIP_INFO(a:PPKCS7_RECIP_INFO;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_SIGNED_new:PPKCS7_SIGNED;cdecl; external DLLUtilName;
procedure PKCS7_SIGNED_free(a:PPKCS7_SIGNED);cdecl; external DLLUtilName;
function  d2i_PKCS7_SIGNED(a:PPPKCS7_SIGNED;_in:Ppbyte; len:clong):PPKCS7_SIGNED;cdecl; external DLLUtilName;
function  i2d_PKCS7_SIGNED(a:PPKCS7_SIGNED;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_ENC_CONTENT_new:PPKCS7_ENC_CONTENT;cdecl; external DLLUtilName;
procedure PKCS7_ENC_CONTENT_free(a:PPKCS7_ENC_CONTENT);cdecl; external DLLUtilName;
function  d2i_PKCS7_ENC_CONTENT(a:PPPKCS7_ENC_CONTENT;_in:Ppbyte; len:clong):PPKCS7_ENC_CONTENT;cdecl; external DLLUtilName;
function  i2d_PKCS7_ENC_CONTENT(a:PPKCS7_ENC_CONTENT;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_ENVELOPE_new:PPKCS7_ENVELOPE;cdecl; external DLLUtilName;
procedure PKCS7_ENVELOPE_free(a:PPKCS7_ENVELOPE);cdecl; external DLLUtilName;
function  d2i_PKCS7_ENVELOPE(a:PPPKCS7_ENVELOPE;_in:Ppbyte; len:clong):PPKCS7_ENVELOPE;cdecl; external DLLUtilName;
function  i2d_PKCS7_ENVELOPE(a:PPKCS7_ENVELOPE;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_SIGN_ENVELOPE_new:PPKCS7_SIGN_ENVELOPE;cdecl; external DLLUtilName;
procedure PKCS7_SIGN_ENVELOPE_free(a:PPKCS7_SIGN_ENVELOPE);cdecl; external DLLUtilName;
function  d2i_PKCS7_SIGN_ENVELOPE(a:PPPKCS7_SIGN_ENVELOPE;_in:Ppbyte; len:clong):PPKCS7_SIGN_ENVELOPE;cdecl; external DLLUtilName;
function  i2d_PKCS7_SIGN_ENVELOPE(a:PPKCS7_SIGN_ENVELOPE;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_DIGEST_new:PPKCS7_DIGEST;cdecl; external DLLUtilName;
procedure PKCS7_DIGEST_free(a:PPKCS7_DIGEST);cdecl; external DLLUtilName;
function  d2i_PKCS7_DIGEST(a:PPPKCS7_DIGEST;_in:Ppbyte; len:clong):PPKCS7_DIGEST;cdecl; external DLLUtilName;
function  i2d_PKCS7_DIGEST(a:PPKCS7_DIGEST;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_ENCRYPT_new:PPKCS7_ENCRYPT;cdecl; external DLLUtilName;
procedure PKCS7_ENCRYPT_free(a:PPKCS7_ENCRYPT);cdecl; external DLLUtilName;
function  d2i_PKCS7_ENCRYPT(a:PPPKCS7_ENCRYPT;_in:Ppbyte; len:clong):PPKCS7_ENCRYPT;cdecl; external DLLUtilName;
function  i2d_PKCS7_ENCRYPT(a:PPKCS7_ENCRYPT;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS7_new:PPKCS7;cdecl; external DLLUtilName;
procedure PKCS7_free(a:PPKCS7);cdecl; external DLLUtilName;
function  d2i_PKCS7(a:PPPKCS7;_in:Ppbyte; len:clong):PPKCS7;cdecl; external DLLUtilName;
function  i2d_PKCS7(a:PPKCS7;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  i2d_PKCS7_NDEF(a:PPKCS7;_out:Ppbyte):cint;cdecl; external DLLUtilName;
function  PKCS7_print_ctx(_out:PBIO; x:PPKCS7; indent:cint; pctx:PASN1_PCTX):cint;cdecl; external DLLUtilName;
function  PKCS7_ctrl(p7:PPKCS7; cmd:cint; larg:clong; parg:pbyte):clong;cdecl; external DLLUtilName;
function  PKCS7_set_type(p7:PPKCS7; _type:cint):cint;cdecl; external DLLUtilName;
function  PKCS7_set0_type_other(p7:PPKCS7; _type:cint; other:PASN1_TYPE):cint;cdecl; external DLLUtilName;
function  PKCS7_set_content(p7:PPKCS7; p7_data:PPKCS7):cint;cdecl; external DLLUtilName;
function  PKCS7_SIGNER_INFO_set(p7i:PPKCS7_SIGNER_INFO; x509:PX509; pkey:PEVP_PKEY; dgst:PEVP_MD):cint;cdecl; external DLLUtilName;
function  PKCS7_SIGNER_INFO_sign(si:PPKCS7_SIGNER_INFO):cint;cdecl; external DLLUtilName;
function  PKCS7_add_signer(p7:PPKCS7; p7i:PPKCS7_SIGNER_INFO):cint;cdecl; external DLLUtilName;
function  PKCS7_add_certificate(p7:PPKCS7; x509:PX509):cint;cdecl; external DLLUtilName;
function  PKCS7_add_crl(p7:PPKCS7; x509:PX509_CRL):cint;cdecl; external DLLUtilName;
function  PKCS7_content_new(p7:PPKCS7; nid:cint):cint;cdecl; external DLLUtilName;
function  PKCS7_dataVerify(cert_store:PX509_STORE; ctx:PX509_STORE_CTX; bio:PBIO; p7:PPKCS7; si:PPKCS7_SIGNER_INFO):cint;cdecl; external DLLUtilName;
function  PKCS7_signatureVerify(bio:PBIO; p7:PPKCS7; si:PPKCS7_SIGNER_INFO; x509:PX509):cint;cdecl; external DLLUtilName;
function  PKCS7_dataInit(p7:PPKCS7; bio:PBIO):PBIO;cdecl; external DLLUtilName;
function  PKCS7_dataFinal(p7:PPKCS7; bio:PBIO):cint;cdecl; external DLLUtilName;
function  PKCS7_dataDecode(p7:PPKCS7; pkey:PEVP_PKEY; in_bio:PBIO; pcert:PX509):PBIO;cdecl; external DLLUtilName;
function  PKCS7_add_signature(p7:PPKCS7; x509:PX509; pkey:PEVP_PKEY; dgst:PEVP_MD):PPKCS7_SIGNER_INFO;cdecl; external DLLUtilName;
function  PKCS7_cert_from_signer_info(p7:PPKCS7; si:PPKCS7_SIGNER_INFO):PX509;cdecl; external DLLUtilName;
function  PKCS7_set_digest(p7:PPKCS7; md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  PKCS7_add_recipient(p7:PPKCS7; x509:PX509):PPKCS7_RECIP_INFO;cdecl; external DLLUtilName;
procedure PKCS7_SIGNER_INFO_get0_algs(si:PPKCS7_SIGNER_INFO; pk:PPEVP_PKEY; pdig:PPX509_ALGOR; psig:PPX509_ALGOR);cdecl; external DLLUtilName;
procedure PKCS7_RECIP_INFO_get0_alg(ri:PPKCS7_RECIP_INFO; penc:PPX509_ALGOR);cdecl; external DLLUtilName;
function  PKCS7_add_recipient_info(p7:PPKCS7; ri:PPKCS7_RECIP_INFO):cint;cdecl; external DLLUtilName;
function  PKCS7_RECIP_INFO_set(p7i:PPKCS7_RECIP_INFO; x509:PX509):cint;cdecl; external DLLUtilName;
function  PKCS7_set_cipher(p7:PPKCS7; cipher:PEVP_CIPHER):cint;cdecl; external DLLUtilName;

function  PKCS7_stream(boundary:PPpbyte; p7:PPKCS7):cint;cdecl; external DLLUtilName;
function  PKCS7_get_issuer_and_serial(p7:PPKCS7; idx:cint):PPKCS7_ISSUER_AND_SERIAL;cdecl; external DLLUtilName;
function  PKCS7_digest_from_attributes(sk:Pstack_st_X509_ATTRIBUTE):PASN1_OCTET_STRING;cdecl; external DLLUtilName;
function  PKCS7_add_signed_attribute(p7si:PPKCS7_SIGNER_INFO; nid:cint; _type:cint; data:pointer):cint;cdecl; external DLLUtilName;
function  PKCS7_add_attribute(p7si:PPKCS7_SIGNER_INFO; nid:cint; atrtype:cint; value:pointer):cint;cdecl; external DLLUtilName;
function  PKCS7_get_attribute(si:PPKCS7_SIGNER_INFO; nid:cint):PASN1_TYPE;cdecl; external DLLUtilName;
function  PKCS7_get_signed_attribute(si:PPKCS7_SIGNER_INFO; nid:cint):PASN1_TYPE;cdecl; external DLLUtilName;
function  PKCS7_set_signed_attributes(p7si:PPKCS7_SIGNER_INFO; sk:Pstack_st_X509_ATTRIBUTE):cint;cdecl; external DLLUtilName;
function  PKCS7_set_attributes(p7si:PPKCS7_SIGNER_INFO; sk:Pstack_st_X509_ATTRIBUTE):cint;cdecl; external DLLUtilName;
function  PKCS7_sign(signcert:PX509; pkey:PEVP_PKEY; certs:Pstack_st_X509; data:PBIO; flags:cint):PPKCS7;cdecl; external DLLUtilName;
function  PKCS7_sign_add_signer(p7:PPKCS7; signcert:PX509; pkey:PEVP_PKEY; md:PEVP_MD; flags:cint):PPKCS7_SIGNER_INFO;cdecl; external DLLUtilName;
function  PKCS7_final(p7:PPKCS7; data:PBIO; flags:cint):cint;cdecl; external DLLUtilName;
function  PKCS7_verify(p7:PPKCS7; certs:Pstack_st_X509; store:PX509_STORE; indata:PBIO;_out:PBIO; 
               flags:cint):cint;cdecl; external DLLUtilName;
function  PKCS7_encrypt(certs:Pstack_st_X509;_in:PBIO; cipher:PEVP_CIPHER; flags:cint):PPKCS7;cdecl; external DLLUtilName;
function  PKCS7_decrypt(p7:PPKCS7; pkey:PEVP_PKEY; cert:PX509; data:PBIO; flags:cint):cint;cdecl; external DLLUtilName;
function  PKCS7_add_attrib_smimecap(si:PPKCS7_SIGNER_INFO; cap:Pstack_st_X509_ALGOR):cint;cdecl; external DLLUtilName;
function  PKCS7_simple_smimecap(sk:Pstack_st_X509_ALGOR; nid:cint; arg:cint):cint;cdecl; external DLLUtilName;
function  PKCS7_add_attrib_content_type(si:PPKCS7_SIGNER_INFO; coid:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  PKCS7_add0_attrib_signing_time(si:PPKCS7_SIGNER_INFO; t:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  PKCS7_add1_attrib_digest(si:PPKCS7_SIGNER_INFO; md:pbyte; mdlen:cint):cint;cdecl; external DLLUtilName;
function  SMIME_write_PKCS7(bio:PBIO; p7:PPKCS7; data:PBIO; flags:cint):cint;cdecl; external DLLUtilName;
function  SMIME_read_PKCS7(bio:PBIO; bcont:PPBIO):PPKCS7;cdecl; external DLLUtilName;
function  BIO_new_PKCS7(_out:PBIO; p7:PPKCS7):PBIO;cdecl; external DLLUtilName;
function  ERR_load_PKCS7_strings:cint;cdecl; external DLLUtilName;
    const
      PKCS7_F_DO_PKCS7_SIGNED_ATTRIB = 136;      
      PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME = 135;      
      PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP = 118;      
      PKCS7_F_PKCS7_ADD_CERTIFICATE = 100;      
      PKCS7_F_PKCS7_ADD_CRL = 101;      
      PKCS7_F_PKCS7_ADD_RECIPIENT_INFO = 102;      
      PKCS7_F_PKCS7_ADD_SIGNATURE = 131;      
      PKCS7_F_PKCS7_ADD_SIGNER = 103;      
      PKCS7_F_PKCS7_BIO_ADD_DIGEST = 125;      
      PKCS7_F_PKCS7_COPY_EXISTING_DIGEST = 138;      
      PKCS7_F_PKCS7_CTRL = 104;      
      PKCS7_F_PKCS7_DATADECODE = 112;      
      PKCS7_F_PKCS7_DATAFINAL = 128;      
      PKCS7_F_PKCS7_DATAINIT = 105;      
      PKCS7_F_PKCS7_DATAVERIFY = 107;      
      PKCS7_F_PKCS7_DECRYPT = 114;      
      PKCS7_F_PKCS7_DECRYPT_RINFO = 133;      
      PKCS7_F_PKCS7_ENCODE_RINFO = 132;      
      PKCS7_F_PKCS7_ENCRYPT = 115;      
      PKCS7_F_PKCS7_FINAL = 134;      
      PKCS7_F_PKCS7_FIND_DIGEST = 127;      
      PKCS7_F_PKCS7_GET0_SIGNERS = 124;      
      PKCS7_F_PKCS7_RECIP_INFO_SET = 130;      
      PKCS7_F_PKCS7_SET_CIPHER = 108;      
      PKCS7_F_PKCS7_SET_CONTENT = 109;      
      PKCS7_F_PKCS7_SET_DIGEST = 126;      
      PKCS7_F_PKCS7_SET_TYPE = 110;      
      PKCS7_F_PKCS7_SIGN = 116;      
      PKCS7_F_PKCS7_SIGNATUREVERIFY = 113;      
      PKCS7_F_PKCS7_SIGNER_INFO_SET = 129;      
      PKCS7_F_PKCS7_SIGNER_INFO_SIGN = 139;      
      PKCS7_F_PKCS7_SIGN_ADD_SIGNER = 137;      
      PKCS7_F_PKCS7_SIMPLE_SMIMECAP = 119;      
      PKCS7_F_PKCS7_VERIFY = 117;      
      PKCS7_R_CERTIFICATE_VERIFY_ERROR = 117;      
      PKCS7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER = 144;      
      PKCS7_R_CIPHER_NOT_INITIALIZED = 116;      
      PKCS7_R_CONTENT_AND_DATA_PRESENT = 118;      
      PKCS7_R_CTRL_ERROR = 152;      
      PKCS7_R_DECRYPT_ERROR = 119;      
      PKCS7_R_DIGEST_FAILURE = 101;      
      PKCS7_R_ENCRYPTION_CTRL_FAILURE = 149;      
      PKCS7_R_ENCRYPTION_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 150;      
      PKCS7_R_ERROR_ADDING_RECIPIENT = 120;      
      PKCS7_R_ERROR_SETTING_CIPHER = 121;      
      PKCS7_R_INVALID_NULL_POINTER = 143;      
      PKCS7_R_INVALID_SIGNED_DATA_TYPE = 155;      
      PKCS7_R_NO_CONTENT = 122;      
      PKCS7_R_NO_DEFAULT_DIGEST = 151;      
      PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND = 154;      
      PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE = 115;      
      PKCS7_R_NO_SIGNATURES_ON_DATA = 123;      
      PKCS7_R_NO_SIGNERS = 142;      
      PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE = 104;      
      PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR = 124;      
      PKCS7_R_PKCS7_ADD_SIGNER_ERROR = 153;      
      PKCS7_R_PKCS7_DATASIGN = 145;      
      PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE = 127;      
      PKCS7_R_SIGNATURE_FAILURE = 105;      
      PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND = 128;      
      PKCS7_R_SIGNING_CTRL_FAILURE = 147;      
      PKCS7_R_SIGNING_NOT_SUPPORTED_FOR_THIS_KEY_TYPE = 148;      
      PKCS7_R_SMIME_TEXT_ERROR = 129;      
      PKCS7_R_UNABLE_TO_FIND_CERTIFICATE = 106;      
      PKCS7_R_UNABLE_TO_FIND_MEM_BIO = 107;      
      PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST = 108;      
      PKCS7_R_UNKNOWN_DIGEST_TYPE = 109;      
      PKCS7_R_UNKNOWN_OPERATION = 110;      
      PKCS7_R_UNSUPPORTED_CIPHER_TYPE = 111;      
      PKCS7_R_UNSUPPORTED_CONTENT_TYPE = 112;      
      PKCS7_R_WRONG_CONTENT_TYPE = 113;      
      PKCS7_R_WRONG_PKCS7_TYPE = 114;      
      X509_EXT_PACK_UNKNOWN = 1;      
      X509_EXT_PACK_STRING = 2;      

    function  X509_extract_key(x : PX509) : PEVP_PKEY;

    function  X509_REQ_extract_key(a : PX509) : PEVP_PKEY;

type
 TX509_crl_init_cb=function  (crl:PX509_CRL):cint;cdecl;
 TX509_crl_lookup_cb=function  (crl:PX509_CRL; ret:PPX509_REVOKED; ser:PASN1_INTEGER; issuer:PX509_NAME):cint;cdecl;
 TX509_crl_verify_cb=function  (crl:PX509_CRL; pk:PEVP_PKEY):cint;cdecl;


procedure X509_CRL_set_default_method(meth:PX509_CRL_METHOD);cdecl; external DLLUtilName;
function  X509_CRL_METHOD_new(crl_init:TX509_crl_init_cb; crl_free:TX509_crl_init_cb; crl_lookup:TX509_crl_lookup_cb; crl_verify:TX509_crl_verify_cb):PX509_CRL_METHOD;cdecl; external DLLUtilName;
procedure X509_CRL_METHOD_free(m:PX509_CRL_METHOD);cdecl; external DLLUtilName;
procedure X509_CRL_set_meth_data(crl:PX509_CRL; dat:pointer);cdecl; external DLLUtilName;
function  X509_CRL_get_meth_data(crl:PX509_CRL):pointer;cdecl; external DLLUtilName;
function  X509_verify_cert_error_string(n:clong):pbyte;cdecl; external DLLUtilName;
function  X509_verify(a:PX509; r:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_REQ_verify(a:PX509_REQ; r:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_CRL_verify(a:PX509_CRL; r:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_verify(a:PNETSCAPE_SPKI; r:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_b64_decode(str:pbyte; len:cint):PNETSCAPE_SPKI;cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_b64_encode(x:PNETSCAPE_SPKI):pbyte;cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_get_pubkey(x:PNETSCAPE_SPKI):PEVP_PKEY;cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_set_pubkey(x:PNETSCAPE_SPKI; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_print(_out:PBIO; spki:PNETSCAPE_SPKI):cint;cdecl; external DLLUtilName;
function  X509_signature_dump(bp:PBIO; sig:PASN1_STRING; indent:cint):cint;cdecl; external DLLUtilName;
function  X509_signature_print(bp:PBIO; alg:PX509_ALGOR; sig:PASN1_STRING):cint;cdecl; external DLLUtilName;
function  X509_sign(x:PX509; pkey:PEVP_PKEY; md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  X509_sign_ctx(x:PX509; ctx:PEVP_MD_CTX):cint;cdecl; external DLLUtilName;
function  X509_http_nbio(rctx:POCSP_REQ_CTX; pcert:PPX509):cint;cdecl; external DLLUtilName;
function  X509_REQ_sign(x:PX509_REQ; pkey:PEVP_PKEY; md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  X509_REQ_sign_ctx(x:PX509_REQ; ctx:PEVP_MD_CTX):cint;cdecl; external DLLUtilName;
function  X509_CRL_sign(x:PX509_CRL; pkey:PEVP_PKEY; md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  X509_CRL_sign_ctx(x:PX509_CRL; ctx:PEVP_MD_CTX):cint;cdecl; external DLLUtilName;
function  X509_CRL_http_nbio(rctx:POCSP_REQ_CTX; pcrl:PPX509_CRL):cint;cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_sign(x:PNETSCAPE_SPKI; pkey:PEVP_PKEY; md:PEVP_MD):cint;cdecl; external DLLUtilName;
function  X509_pubkey_digest(data:PX509; _type:PEVP_MD; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
function  X509_digest(data:PX509; _type:PEVP_MD; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
function  X509_CRL_digest(data:PX509_CRL; _type:PEVP_MD; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
function  X509_REQ_digest(data:PX509_REQ; _type:PEVP_MD; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
function  X509_NAME_digest(data:PX509_NAME; _type:PEVP_MD; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
//function  d2i_X509_fp(fp:PFILE; x509:PPX509):PX509;cdecl; external DLLUtilName;
//function  i2d_X509_fp(fp:PFILE; x509:PX509):cint;cdecl; external DLLUtilName;
//function  d2i_X509_CRL_fp(fp:PFILE; crl:PPX509_CRL):PX509_CRL;cdecl; external DLLUtilName;
//function  i2d_X509_CRL_fp(fp:PFILE; crl:PX509_CRL):cint;cdecl; external DLLUtilName;
//function  d2i_X509_REQ_fp(fp:PFILE; req:PPX509_REQ):PX509_REQ;cdecl; external DLLUtilName;
//function  i2d_X509_REQ_fp(fp:PFILE; req:PX509_REQ):cint;cdecl; external DLLUtilName;
//function  d2i_RSAPrivateKey_fp(fp:PFILE; rsa:PPRSA):PRSA;cdecl; external DLLUtilName;
//function  i2d_RSAPrivateKey_fp(fp:PFILE; rsa:PRSA):cint;cdecl; external DLLUtilName;
//function  d2i_RSAPublicKey_fp(fp:PFILE; rsa:PPRSA):PRSA;cdecl; external DLLUtilName;
//function  i2d_RSAPublicKey_fp(fp:PFILE; rsa:PRSA):cint;cdecl; external DLLUtilName;
//function  d2i_RSA_PUBKEY_fp(fp:PFILE; rsa:PPRSA):PRSA;cdecl; external DLLUtilName;
//function  i2d_RSA_PUBKEY_fp(fp:PFILE; rsa:PRSA):cint;cdecl; external DLLUtilName;
//function  d2i_DSA_PUBKEY_fp(fp:PFILE; dsa:PPDSA):PDSA;cdecl; external DLLUtilName;
//function  i2d_DSA_PUBKEY_fp(fp:PFILE; dsa:PDSA):cint;cdecl; external DLLUtilName;
//function  d2i_DSAPrivateKey_fp(fp:PFILE; dsa:PPDSA):PDSA;cdecl; external DLLUtilName;
//function  i2d_DSAPrivateKey_fp(fp:PFILE; dsa:PDSA):cint;cdecl; external DLLUtilName;
//function  d2i_EC_PUBKEY_fp(fp:PFILE; eckey:PPEC_KEY):PEC_KEY;cdecl; external DLLUtilName;
//function  i2d_EC_PUBKEY_fp(fp:PFILE; eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
//function  d2i_ECPrivateKey_fp(fp:PFILE; eckey:PPEC_KEY):PEC_KEY;cdecl; external DLLUtilName;
//function  i2d_ECPrivateKey_fp(fp:PFILE; eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
//function  d2i_PKCS8_fp(fp:PFILE; p8:PPX509_SIG):PX509_SIG;cdecl; external DLLUtilName;
//function  i2d_PKCS8_fp(fp:PFILE; p8:PX509_SIG):cint;cdecl; external DLLUtilName;
//function  d2i_PKCS8_PRIV_KEY_INFO_fp(fp:PFILE; p8inf:PPPKCS8_PRIV_KEY_INFO):PPKCS8_PRIV_KEY_INFO;cdecl; external DLLUtilName;
//function  i2d_PKCS8_PRIV_KEY_INFO_fp(fp:PFILE; p8inf:PPKCS8_PRIV_KEY_INFO):cint;cdecl; external DLLUtilName;
//function  i2d_PKCS8PrivateKeyInfo_fp(fp:PFILE; key:PEVP_PKEY):cint;cdecl; external DLLUtilName;
//function  i2d_PrivateKey_fp(fp:PFILE; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
//function  d2i_PrivateKey_fp(fp:PFILE; a:PPEVP_PKEY):PEVP_PKEY;cdecl; external DLLUtilName;
//function  i2d_PUBKEY_fp(fp:PFILE; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
//function  d2i_PUBKEY_fp(fp:PFILE; a:PPEVP_PKEY):PEVP_PKEY;cdecl; external DLLUtilName;
function  d2i_X509_bio(bp:PBIO; x509:PPX509):PX509;cdecl; external DLLUtilName;
function  i2d_X509_bio(bp:PBIO; x509:PX509):cint;cdecl; external DLLUtilName;
function  d2i_X509_CRL_bio(bp:PBIO; crl:PPX509_CRL):PX509_CRL;cdecl; external DLLUtilName;
function  i2d_X509_CRL_bio(bp:PBIO; crl:PX509_CRL):cint;cdecl; external DLLUtilName;
function  d2i_X509_REQ_bio(bp:PBIO; req:PPX509_REQ):PX509_REQ;cdecl; external DLLUtilName;
function  i2d_X509_REQ_bio(bp:PBIO; req:PX509_REQ):cint;cdecl; external DLLUtilName;
function  d2i_RSAPrivateKey_bio(bp:PBIO; rsa:PPRSA):PRSA;cdecl; external DLLUtilName;
function  i2d_RSAPrivateKey_bio(bp:PBIO; rsa:PRSA):cint;cdecl; external DLLUtilName;
function  d2i_RSAPublicKey_bio(bp:PBIO; rsa:PPRSA):PRSA;cdecl; external DLLUtilName;
function  i2d_RSAPublicKey_bio(bp:PBIO; rsa:PRSA):cint;cdecl; external DLLUtilName;
function  d2i_RSA_PUBKEY_bio(bp:PBIO; rsa:PPRSA):PRSA;cdecl; external DLLUtilName;
function  i2d_RSA_PUBKEY_bio(bp:PBIO; rsa:PRSA):cint;cdecl; external DLLUtilName;
function  d2i_DSA_PUBKEY_bio(bp:PBIO; dsa:PPDSA):PDSA;cdecl; external DLLUtilName;
function  i2d_DSA_PUBKEY_bio(bp:PBIO; dsa:PDSA):cint;cdecl; external DLLUtilName;
function  d2i_DSAPrivateKey_bio(bp:PBIO; dsa:PPDSA):PDSA;cdecl; external DLLUtilName;
function  i2d_DSAPrivateKey_bio(bp:PBIO; dsa:PDSA):cint;cdecl; external DLLUtilName;
function  d2i_EC_PUBKEY_bio(bp:PBIO; eckey:PPEC_KEY):PEC_KEY;cdecl; external DLLUtilName;
function  i2d_EC_PUBKEY_bio(bp:PBIO; eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  d2i_ECPrivateKey_bio(bp:PBIO; eckey:PPEC_KEY):PEC_KEY;cdecl; external DLLUtilName;
function  i2d_ECPrivateKey_bio(bp:PBIO; eckey:PEC_KEY):cint;cdecl; external DLLUtilName;
function  d2i_PKCS8_bio(bp:PBIO; p8:PPX509_SIG):PX509_SIG;cdecl; external DLLUtilName;
function  i2d_PKCS8_bio(bp:PBIO; p8:PX509_SIG):cint;cdecl; external DLLUtilName;
function  d2i_PKCS8_PRIV_KEY_INFO_bio(bp:PBIO; p8inf:PPPKCS8_PRIV_KEY_INFO):PPKCS8_PRIV_KEY_INFO;cdecl; external DLLUtilName;
function  i2d_PKCS8_PRIV_KEY_INFO_bio(bp:PBIO; p8inf:PPKCS8_PRIV_KEY_INFO):cint;cdecl; external DLLUtilName;
function  i2d_PKCS8PrivateKeyInfo_bio(bp:PBIO; key:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  i2d_PrivateKey_bio(bp:PBIO; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  d2i_PrivateKey_bio(bp:PBIO; a:PPEVP_PKEY):PEVP_PKEY;cdecl; external DLLUtilName;
function  i2d_PUBKEY_bio(bp:PBIO; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  d2i_PUBKEY_bio(bp:PBIO; a:PPEVP_PKEY):PEVP_PKEY;cdecl; external DLLUtilName;
function  X509_dup(x509:PX509):PX509;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_dup(xa:PX509_ATTRIBUTE):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509_EXTENSION_dup(ex:PX509_EXTENSION):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_CRL_dup(crl:PX509_CRL):PX509_CRL;cdecl; external DLLUtilName;
function  X509_REVOKED_dup(rev:PX509_REVOKED):PX509_REVOKED;cdecl; external DLLUtilName;
function  X509_REQ_dup(req:PX509_REQ):PX509_REQ;cdecl; external DLLUtilName;
function  X509_ALGOR_dup(xn:PX509_ALGOR):PX509_ALGOR;cdecl; external DLLUtilName;
function  X509_ALGOR_set0(alg:PX509_ALGOR; aobj:PASN1_OBJECT; ptype:cint; pval:pointer):cint;cdecl; external DLLUtilName;
procedure X509_ALGOR_get0(paobj:PPASN1_OBJECT; pptype:pcint; ppval:Ppointer; algor:PX509_ALGOR);cdecl; external DLLUtilName;
procedure X509_ALGOR_set_md(alg:PX509_ALGOR; md:PEVP_MD);cdecl; external DLLUtilName;
function  X509_ALGOR_cmp(a:PX509_ALGOR; b:PX509_ALGOR):cint;cdecl; external DLLUtilName;
function  X509_NAME_dup(xn:PX509_NAME):PX509_NAME;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_dup(ne:PX509_NAME_ENTRY):PX509_NAME_ENTRY;cdecl; external DLLUtilName;
function  X509_cmp_time(s:PASN1_TIME; t:Ptime_t):cint;cdecl; external DLLUtilName;
function  X509_cmp_current_time(s:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  X509_time_adj(s:PASN1_TIME; adj:clong; t:Ptime_t):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_time_adj_ex(s:PASN1_TIME; offset_day:cint; offset_sec:clong; t:Ptime_t):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_gmtime_adj(s:PASN1_TIME; adj:clong):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_get_default_cert_area:pbyte;cdecl; external DLLUtilName;
function  X509_get_default_cert_dir:pbyte;cdecl; external DLLUtilName;
function  X509_get_default_cert_file:pbyte;cdecl; external DLLUtilName;
function  X509_get_default_cert_dir_env:pbyte;cdecl; external DLLUtilName;
function  X509_get_default_cert_file_env:pbyte;cdecl; external DLLUtilName;
function  X509_get_default_private_dir:pbyte;cdecl; external DLLUtilName;
function  X509_to_X509_REQ(x:PX509; pkey:PEVP_PKEY; md:PEVP_MD):PX509_REQ;cdecl; external DLLUtilName;
function  X509_REQ_to_X509(r:PX509_REQ; days:cint; pkey:PEVP_PKEY):PX509;cdecl; external DLLUtilName;
function  X509_ALGOR_new:PX509_ALGOR;cdecl; external DLLUtilName;
procedure X509_ALGOR_free(a:PX509_ALGOR);cdecl; external DLLUtilName;
function  d2i_X509_ALGOR(a:PPX509_ALGOR;_in:Ppbyte; len:clong):PX509_ALGOR;cdecl; external DLLUtilName;
function  i2d_X509_ALGOR(a:PX509_ALGOR;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  d2i_X509_ALGORS(a:PPX509_ALGORS;_in:Ppbyte; len:clong):PX509_ALGORS;cdecl; external DLLUtilName;
function  i2d_X509_ALGORS(a:PX509_ALGORS;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_VAL_new:PX509_VAL;cdecl; external DLLUtilName;
procedure X509_VAL_free(a:PX509_VAL);cdecl; external DLLUtilName;
function  d2i_X509_VAL(a:PPX509_VAL;_in:Ppbyte; len:clong):PX509_VAL;cdecl; external DLLUtilName;
function  i2d_X509_VAL(a:PX509_VAL;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_PUBKEY_new:PX509_PUBKEY;cdecl; external DLLUtilName;
procedure X509_PUBKEY_free(a:PX509_PUBKEY);cdecl; external DLLUtilName;
function  d2i_X509_PUBKEY(a:PPX509_PUBKEY;_in:Ppbyte; len:clong):PX509_PUBKEY;cdecl; external DLLUtilName;
function  i2d_X509_PUBKEY(a:PX509_PUBKEY;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_PUBKEY_set(x:PPX509_PUBKEY; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_PUBKEY_get0(key:PX509_PUBKEY):PEVP_PKEY;cdecl; external DLLUtilName;
function  X509_PUBKEY_get(key:PX509_PUBKEY):PEVP_PKEY;cdecl; external DLLUtilName;
function  X509_get_pubkey_parameters(pkey:PEVP_PKEY; chain:Pstack_st_X509):cint;cdecl; external DLLUtilName;
function  X509_get_pathlen(x:PX509):clong;cdecl; external DLLUtilName;
function  i2d_PUBKEY(a:PEVP_PKEY; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_PUBKEY(a:PPEVP_PKEY; pp:Ppbyte; length:clong):PEVP_PKEY;cdecl; external DLLUtilName;
function  i2d_RSA_PUBKEY(a:PRSA; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_RSA_PUBKEY(a:PPRSA; pp:Ppbyte; length:clong):PRSA;cdecl; external DLLUtilName;
function  i2d_DSA_PUBKEY(a:PDSA; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_DSA_PUBKEY(a:PPDSA; pp:Ppbyte; length:clong):PDSA;cdecl; external DLLUtilName;
function  i2d_EC_PUBKEY(a:PEC_KEY; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_EC_PUBKEY(a:PPEC_KEY; pp:Ppbyte; length:clong):PEC_KEY;cdecl; external DLLUtilName;
function  X509_SIG_new:PX509_SIG;cdecl; external DLLUtilName;
procedure X509_SIG_free(a:PX509_SIG);cdecl; external DLLUtilName;
function  d2i_X509_SIG(a:PPX509_SIG;_in:Ppbyte; len:clong):PX509_SIG;cdecl; external DLLUtilName;
function  i2d_X509_SIG(a:PX509_SIG;_out:Ppbyte):cint;cdecl; external DLLUtilName;

procedure X509_SIG_get0(sig:PX509_SIG; palg:PPX509_ALGOR; pdigest:PPASN1_OCTET_STRING);cdecl; external DLLUtilName;
procedure X509_SIG_getm(sig:PX509_SIG; palg:PPX509_ALGOR; pdigest:PPASN1_OCTET_STRING);cdecl; external DLLUtilName;
function  X509_REQ_INFO_new:PX509_REQ_INFO;cdecl; external DLLUtilName;
procedure X509_REQ_INFO_free(a:PX509_REQ_INFO);cdecl; external DLLUtilName;
function  d2i_X509_REQ_INFO(a:PPX509_REQ_INFO;_in:Ppbyte; len:clong):PX509_REQ_INFO;cdecl; external DLLUtilName;
function  i2d_X509_REQ_INFO(a:PX509_REQ_INFO;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_REQ_new:PX509_REQ;cdecl; external DLLUtilName;
procedure X509_REQ_free(a:PX509_REQ);cdecl; external DLLUtilName;
function  d2i_X509_REQ(a:PPX509_REQ;_in:Ppbyte; len:clong):PX509_REQ;cdecl; external DLLUtilName;
function  i2d_X509_REQ(a:PX509_REQ;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_ATTRIBUTE_new:PX509_ATTRIBUTE;cdecl; external DLLUtilName;
procedure X509_ATTRIBUTE_free(a:PX509_ATTRIBUTE);cdecl; external DLLUtilName;
function  d2i_X509_ATTRIBUTE(a:PPX509_ATTRIBUTE;_in:Ppbyte; len:clong):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  i2d_X509_ATTRIBUTE(a:PX509_ATTRIBUTE;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_ATTRIBUTE_create(nid:cint; atrtype:cint; value:pointer):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509_EXTENSION_new:PX509_EXTENSION;cdecl; external DLLUtilName;
procedure X509_EXTENSION_free(a:PX509_EXTENSION);cdecl; external DLLUtilName;
function  d2i_X509_EXTENSION(a:PPX509_EXTENSION;_in:Ppbyte; len:clong):PX509_EXTENSION;cdecl; external DLLUtilName;
function  i2d_X509_EXTENSION(a:PX509_EXTENSION;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  d2i_X509_EXTENSIONS(a:PPX509_EXTENSIONS;_in:Ppbyte; len:clong):PX509_EXTENSIONS;cdecl; external DLLUtilName;
function  i2d_X509_EXTENSIONS(a:PX509_EXTENSIONS;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_NAME_ENTRY_new:PX509_NAME_ENTRY;cdecl; external DLLUtilName;
procedure X509_NAME_ENTRY_free(a:PX509_NAME_ENTRY);cdecl; external DLLUtilName;
function  d2i_X509_NAME_ENTRY(a:PPX509_NAME_ENTRY;_in:Ppbyte; len:clong):PX509_NAME_ENTRY;cdecl; external DLLUtilName;
function  i2d_X509_NAME_ENTRY(a:PX509_NAME_ENTRY;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_NAME_new:PX509_NAME;cdecl; external DLLUtilName;
procedure X509_NAME_free(a:PX509_NAME);cdecl; external DLLUtilName;
function  d2i_X509_NAME(a:PPX509_NAME;_in:Ppbyte; len:clong):PX509_NAME;cdecl; external DLLUtilName;
function  i2d_X509_NAME(a:PX509_NAME;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_NAME_set(xn:PPX509_NAME; name:PX509_NAME):cint;cdecl; external DLLUtilName;
function  X509_CINF_new:PX509_CINF;cdecl; external DLLUtilName;
procedure X509_CINF_free(a:PX509_CINF);cdecl; external DLLUtilName;
function  d2i_X509_CINF(a:PPX509_CINF;_in:Ppbyte; len:clong):PX509_CINF;cdecl; external DLLUtilName;
function  i2d_X509_CINF(a:PX509_CINF;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_new:PX509;cdecl; external DLLUtilName;
procedure X509_free(a:PX509);cdecl; external DLLUtilName;
function  d2i_X509(a:PPX509;_in:Ppbyte; len:clong):PX509;cdecl; external DLLUtilName;
function  i2d_X509(a:PX509;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_CERT_AUX_new:PX509_CERT_AUX;cdecl; external DLLUtilName;
procedure X509_CERT_AUX_free(a:PX509_CERT_AUX);cdecl; external DLLUtilName;
function  d2i_X509_CERT_AUX(a:PPX509_CERT_AUX;_in:Ppbyte; len:clong):PX509_CERT_AUX;cdecl; external DLLUtilName;
function  i2d_X509_CERT_AUX(a:PX509_CERT_AUX;_out:Ppbyte):cint;cdecl; external DLLUtilName;

    function  X509_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  X509_set_ex_data(r:PX509; idx:cint; arg:pointer):cint;cdecl; external DLLUtilName;
function  X509_get_ex_data(r:PX509; idx:cint):pointer;cdecl; external DLLUtilName;
function  i2d_X509_AUX(a:PX509; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  d2i_X509_AUX(a:PPX509; pp:Ppbyte; length:clong):PX509;cdecl; external DLLUtilName;
function  i2d_re_X509_tbs(x:PX509; pp:Ppbyte):cint;cdecl; external DLLUtilName;
procedure X509_get0_signature(psig:PPASN1_BIT_STRING; palg:PPX509_ALGOR; x:PX509);cdecl; external DLLUtilName;
function  X509_get_signature_nid(x:PX509):cint;cdecl; external DLLUtilName;
function  X509_trusted(x:PX509):cint;cdecl; external DLLUtilName;
function  X509_alias_set1(x:PX509; name:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_keyid_set1(x:PX509; id:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_alias_get0(x:PX509; len:pcint):pbyte;cdecl; external DLLUtilName;
function  X509_keyid_get0(x:PX509; len:pcint):pbyte;cdecl; external DLLUtilName;

type
 TX509_trust_cb=function  (para1:cint; para2:PX509; para3:cint):cint;cdecl;

function  X509_TRUST_set_default(trust:TX509_trust_cb):TX509_trust_cb;cdecl; external DLLUtilName;
function  X509_TRUST_set(t:pcint; trust:cint):cint;cdecl; external DLLUtilName;
function  X509_add1_trust_object(x:PX509; obj:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_add1_reject_object(x:PX509; obj:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
procedure X509_trust_clear(x:PX509);cdecl; external DLLUtilName;
procedure X509_reject_clear(x:PX509);cdecl; external DLLUtilName;
function  X509_REVOKED_new:PX509_REVOKED;cdecl; external DLLUtilName;
procedure X509_REVOKED_free(a:PX509_REVOKED);cdecl; external DLLUtilName;
function  d2i_X509_REVOKED(a:PPX509_REVOKED;_in:Ppbyte; len:clong):PX509_REVOKED;cdecl; external DLLUtilName;
function  i2d_X509_REVOKED(a:PX509_REVOKED;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_CRL_INFO_new:PX509_CRL_INFO;cdecl; external DLLUtilName;
procedure X509_CRL_INFO_free(a:PX509_CRL_INFO);cdecl; external DLLUtilName;
function  d2i_X509_CRL_INFO(a:PPX509_CRL_INFO;_in:Ppbyte; len:clong):PX509_CRL_INFO;cdecl; external DLLUtilName;
function  i2d_X509_CRL_INFO(a:PX509_CRL_INFO;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_CRL_new:PX509_CRL;cdecl; external DLLUtilName;
procedure X509_CRL_free(a:PX509_CRL);cdecl; external DLLUtilName;
function  d2i_X509_CRL(a:PPX509_CRL;_in:Ppbyte; len:clong):PX509_CRL;cdecl; external DLLUtilName;
function  i2d_X509_CRL(a:PX509_CRL;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_CRL_add0_revoked(crl:PX509_CRL; rev:PX509_REVOKED):cint;cdecl; external DLLUtilName;
function  X509_CRL_get0_by_serial(crl:PX509_CRL; ret:PPX509_REVOKED; serial:PASN1_INTEGER):cint;cdecl; external DLLUtilName;
function  X509_CRL_get0_by_cert(crl:PX509_CRL; ret:PPX509_REVOKED; x:PX509):cint;cdecl; external DLLUtilName;
function  X509_PKEY_new:PX509_PKEY;cdecl; external DLLUtilName;
procedure X509_PKEY_free(a:PX509_PKEY);cdecl; external DLLUtilName;
function  NETSCAPE_SPKI_new:PNETSCAPE_SPKI;cdecl; external DLLUtilName;
procedure NETSCAPE_SPKI_free(a:PNETSCAPE_SPKI);cdecl; external DLLUtilName;
function  d2i_NETSCAPE_SPKI(a:PPNETSCAPE_SPKI;_in:Ppbyte; len:clong):PNETSCAPE_SPKI;cdecl; external DLLUtilName;
function  i2d_NETSCAPE_SPKI(a:PNETSCAPE_SPKI;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  NETSCAPE_SPKAC_new:PNETSCAPE_SPKAC;cdecl; external DLLUtilName;
procedure NETSCAPE_SPKAC_free(a:PNETSCAPE_SPKAC);cdecl; external DLLUtilName;
function  d2i_NETSCAPE_SPKAC(a:PPNETSCAPE_SPKAC;_in:Ppbyte; len:clong):PNETSCAPE_SPKAC;cdecl; external DLLUtilName;
function  i2d_NETSCAPE_SPKAC(a:PNETSCAPE_SPKAC;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  NETSCAPE_CERT_SEQUENCE_new:PNETSCAPE_CERT_SEQUENCE;cdecl; external DLLUtilName;
procedure NETSCAPE_CERT_SEQUENCE_free(a:PNETSCAPE_CERT_SEQUENCE);cdecl; external DLLUtilName;
function  d2i_NETSCAPE_CERT_SEQUENCE(a:PPNETSCAPE_CERT_SEQUENCE;_in:Ppbyte; len:clong):PNETSCAPE_CERT_SEQUENCE;cdecl; external DLLUtilName;
function  i2d_NETSCAPE_CERT_SEQUENCE(a:PNETSCAPE_CERT_SEQUENCE;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  X509_INFO_new:PX509_INFO;cdecl; external DLLUtilName;
procedure X509_INFO_free(a:PX509_INFO);cdecl; external DLLUtilName;
function  X509_NAME_oneline(a:PX509_NAME; buf:pbyte; size:cint):pbyte;cdecl; external DLLUtilName;
function  ASN1_verify(i2d:Pi2d_of_void; algor1:PX509_ALGOR; signature:PASN1_BIT_STRING; data:pbyte; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  ASN1_digest(i2d:Pi2d_of_void; _type:PEVP_MD; data:pbyte; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
function  ASN1_sign(i2d:Pi2d_of_void; algor1:PX509_ALGOR; algor2:PX509_ALGOR; signature:PASN1_BIT_STRING; data:pbyte; 
               pkey:PEVP_PKEY; _type:PEVP_MD):cint;cdecl; external DLLUtilName;
function  ASN1_item_digest(it:PASN1_ITEM; _type:PEVP_MD; data:pointer; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
function  ASN1_item_verify(it:PASN1_ITEM; algor1:PX509_ALGOR; signature:PASN1_BIT_STRING; data:pointer; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  ASN1_item_sign(it:PASN1_ITEM; algor1:PX509_ALGOR; algor2:PX509_ALGOR; signature:PASN1_BIT_STRING; data:pointer; 
               pkey:PEVP_PKEY; _type:PEVP_MD):cint;cdecl; external DLLUtilName;
function  ASN1_item_sign_ctx(it:PASN1_ITEM; algor1:PX509_ALGOR; algor2:PX509_ALGOR; signature:PASN1_BIT_STRING; asn:pointer; 
               ctx:PEVP_MD_CTX):cint;cdecl; external DLLUtilName;
function  X509_get_version(x:PX509):clong;cdecl; external DLLUtilName;
function  X509_set_version(x:PX509; version:clong):cint;cdecl; external DLLUtilName;
function  X509_set_serialNumber(x:PX509; serial:PASN1_INTEGER):cint;cdecl; external DLLUtilName;
function  X509_get_serialNumber(x:PX509):PASN1_INTEGER;cdecl; external DLLUtilName;
function  X509_get0_serialNumber(x:PX509):PASN1_INTEGER;cdecl; external DLLUtilName;
function  X509_set_issuer_name(x:PX509; name:PX509_NAME):cint;cdecl; external DLLUtilName;
function  X509_get_issuer_name(a:PX509):PX509_NAME;cdecl; external DLLUtilName;
function  X509_set_subject_name(x:PX509; name:PX509_NAME):cint;cdecl; external DLLUtilName;
function  X509_get_subject_name(a:PX509):PX509_NAME;cdecl; external DLLUtilName;
function  X509_get0_notBefore(x:PX509):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_getm_notBefore(x:PX509):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_set1_notBefore(x:PX509; tm:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  X509_get0_notAfter(x:PX509):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_getm_notAfter(x:PX509):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_set1_notAfter(x:PX509; tm:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  X509_set_pubkey(x:PX509; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_up_ref(x:PX509):cint;cdecl; external DLLUtilName;
function  X509_get_signature_type(x:PX509):cint;cdecl; external DLLUtilName;

function  X509_get_X509_PUBKEY(x:PX509):PX509_PUBKEY;cdecl; external DLLUtilName;
function  X509_get0_extensions(x:PX509):Pstack_st_X509_EXTENSION;cdecl; external DLLUtilName;
procedure X509_get0_uids(x:PX509; piuid:PPASN1_BIT_STRING; psuid:PPASN1_BIT_STRING);cdecl; external DLLUtilName;
function  X509_get0_tbs_sigalg(x:PX509):PX509_ALGOR;cdecl; external DLLUtilName;
function  X509_get0_pubkey(x:PX509):PEVP_PKEY;cdecl; external DLLUtilName;
function  X509_get_pubkey(x:PX509):PEVP_PKEY;cdecl; external DLLUtilName;
function  X509_get0_pubkey_bitstr(x:PX509):PASN1_BIT_STRING;cdecl; external DLLUtilName;
function  X509_certificate_type(x:PX509; pubkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_version(req:PX509_REQ):clong;cdecl; external DLLUtilName;
function  X509_REQ_set_version(x:PX509_REQ; version:clong):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_subject_name(req:PX509_REQ):PX509_NAME;cdecl; external DLLUtilName;
function  X509_REQ_set_subject_name(req:PX509_REQ; name:PX509_NAME):cint;cdecl; external DLLUtilName;
procedure X509_REQ_get0_signature(req:PX509_REQ; psig:PPASN1_BIT_STRING; palg:PPX509_ALGOR);cdecl; external DLLUtilName;
function  X509_REQ_get_signature_nid(req:PX509_REQ):cint;cdecl; external DLLUtilName;
function  i2d_re_X509_REQ_tbs(req:PX509_REQ; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  X509_REQ_set_pubkey(x:PX509_REQ; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_pubkey(req:PX509_REQ):PEVP_PKEY;cdecl; external DLLUtilName;
function  X509_REQ_get0_pubkey(req:PX509_REQ):PEVP_PKEY;cdecl; external DLLUtilName;
function  X509_REQ_get_X509_PUBKEY(req:PX509_REQ):PX509_PUBKEY;cdecl; external DLLUtilName;
function  X509_REQ_extension_nid(nid:cint):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_extension_nids:pcint;cdecl; external DLLUtilName;
procedure X509_REQ_set_extension_nids(nids:pcint);cdecl; external DLLUtilName;
function  X509_REQ_add_extensions_nid(req:PX509_REQ; exts:Pstack_st_X509_EXTENSION; nid:cint):cint;cdecl; external DLLUtilName;
function  X509_REQ_add_extensions(req:PX509_REQ; exts:Pstack_st_X509_EXTENSION):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_attr_count(req:PX509_REQ):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_attr_by_NID(req:PX509_REQ; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_attr_by_OBJ(req:PX509_REQ; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_REQ_get_attr(req:PX509_REQ; loc:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509_REQ_delete_attr(req:PX509_REQ; loc:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509_REQ_add1_attr(req:PX509_REQ; attr:PX509_ATTRIBUTE):cint;cdecl; external DLLUtilName;
function  X509_REQ_add1_attr_by_OBJ(req:PX509_REQ; obj:PASN1_OBJECT; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_REQ_add1_attr_by_NID(req:PX509_REQ; nid:cint; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_REQ_add1_attr_by_txt(req:PX509_REQ; attrname:pbyte; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_CRL_set_version(x:PX509_CRL; version:clong):cint;cdecl; external DLLUtilName;
function  X509_CRL_set_issuer_name(x:PX509_CRL; name:PX509_NAME):cint;cdecl; external DLLUtilName;
function  X509_CRL_set1_lastUpdate(x:PX509_CRL; tm:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  X509_CRL_set1_nextUpdate(x:PX509_CRL; tm:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  X509_CRL_sort(crl:PX509_CRL):cint;cdecl; external DLLUtilName;
function  X509_CRL_up_ref(crl:PX509_CRL):cint;cdecl; external DLLUtilName;

function  X509_CRL_get_version(crl:PX509_CRL):clong;cdecl; external DLLUtilName;
function  X509_CRL_get0_lastUpdate(crl:PX509_CRL):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_CRL_get0_nextUpdate(crl:PX509_CRL):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_CRL_get0_extensions(crl:PX509_CRL):Pstack_st_X509_EXTENSION;cdecl; external DLLUtilName;
procedure X509_CRL_get0_signature(crl:PX509_CRL; psig:PPASN1_BIT_STRING; palg:PPX509_ALGOR);cdecl; external DLLUtilName;
function  X509_CRL_get_signature_nid(crl:PX509_CRL):cint;cdecl; external DLLUtilName;
function  i2d_re_X509_CRL_tbs(req:PX509_CRL; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get0_serialNumber(x:PX509_REVOKED):PASN1_INTEGER;cdecl; external DLLUtilName;
function  X509_REVOKED_set_serialNumber(x:PX509_REVOKED; serial:PASN1_INTEGER):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get0_revocationDate(x:PX509_REVOKED):PASN1_TIME;cdecl; external DLLUtilName;
function  X509_REVOKED_set_revocationDate(r:PX509_REVOKED; tm:PASN1_TIME):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get0_extensions(r:PX509_REVOKED):Pstack_st_X509_EXTENSION;cdecl; external DLLUtilName;
function  X509_CRL_diff(base:PX509_CRL; newer:PX509_CRL; skey:PEVP_PKEY; md:PEVP_MD; flags:cuint):PX509_CRL;cdecl; external DLLUtilName;
function  X509_REQ_check_private_key(x509:PX509_REQ; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_check_private_key(x509:PX509; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  X509_chain_check_suiteb(perror_depth:pcint; x:PX509; chain:Pstack_st_X509; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_CRL_check_suiteb(crl:PX509_CRL; pk:PEVP_PKEY; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_issuer_and_serial_cmp(a:PX509; b:PX509):cint;cdecl; external DLLUtilName;
function  X509_issuer_and_serial_hash(a:PX509):culong;cdecl; external DLLUtilName;
function  X509_issuer_name_cmp(a:PX509; b:PX509):cint;cdecl; external DLLUtilName;
function  X509_issuer_name_hash(a:PX509):culong;cdecl; external DLLUtilName;
function  X509_subject_name_cmp(a:PX509; b:PX509):cint;cdecl; external DLLUtilName;
function  X509_subject_name_hash(x:PX509):culong;cdecl; external DLLUtilName;
function  X509_issuer_name_hash_old(a:PX509):culong;cdecl; external DLLUtilName;
function  X509_subject_name_hash_old(x:PX509):culong;cdecl; external DLLUtilName;
function  X509_cmp(a:PX509; b:PX509):cint;cdecl; external DLLUtilName;
function  X509_NAME_cmp(a:PX509_NAME; b:PX509_NAME):cint;cdecl; external DLLUtilName;
function  X509_NAME_hash(x:PX509_NAME):culong;cdecl; external DLLUtilName;
function  X509_NAME_hash_old(x:PX509_NAME):culong;cdecl; external DLLUtilName;
function  X509_CRL_cmp(a:PX509_CRL; b:PX509_CRL):cint;cdecl; external DLLUtilName;
function  X509_CRL_match(a:PX509_CRL; b:PX509_CRL):cint;cdecl; external DLLUtilName;
function  X509_aux_print(_out:PBIO; x:PX509; indent:cint):cint;cdecl; external DLLUtilName;
//function  X509_print_ex_fp(bp:PFILE; x:PX509; nmflag:culong; cflag:culong):cint;cdecl; external DLLUtilName;
//function  X509_print_fp(bp:PFILE; x:PX509):cint;cdecl; external DLLUtilName;
//function  X509_CRL_print_fp(bp:PFILE; x:PX509_CRL):cint;cdecl; external DLLUtilName;
//function  X509_REQ_print_fp(bp:PFILE; req:PX509_REQ):cint;cdecl; external DLLUtilName;
//function  X509_NAME_print_ex_fp(fp:PFILE; nm:PX509_NAME; indent:cint; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_NAME_print(bp:PBIO; name:PX509_NAME; obase:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_print_ex(_out:PBIO; nm:PX509_NAME; indent:cint; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_print_ex(bp:PBIO; x:PX509; nmflag:culong; cflag:culong):cint;cdecl; external DLLUtilName;
function  X509_print(bp:PBIO; x:PX509):cint;cdecl; external DLLUtilName;
function  X509_ocspid_print(bp:PBIO; x:PX509):cint;cdecl; external DLLUtilName;
function  X509_CRL_print(bp:PBIO; x:PX509_CRL):cint;cdecl; external DLLUtilName;
function  X509_REQ_print_ex(bp:PBIO; x:PX509_REQ; nmflag:culong; cflag:culong):cint;cdecl; external DLLUtilName;
function  X509_REQ_print(bp:PBIO; req:PX509_REQ):cint;cdecl; external DLLUtilName;
function  X509_NAME_entry_count(name:PX509_NAME):cint;cdecl; external DLLUtilName;
function  X509_NAME_get_text_by_NID(name:PX509_NAME; nid:cint; buf:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_get_text_by_OBJ(name:PX509_NAME; obj:PASN1_OBJECT; buf:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_get_index_by_NID(name:PX509_NAME; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_get_index_by_OBJ(name:PX509_NAME; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_get_entry(name:PX509_NAME; loc:cint):PX509_NAME_ENTRY;cdecl; external DLLUtilName;
function  X509_NAME_delete_entry(name:PX509_NAME; loc:cint):PX509_NAME_ENTRY;cdecl; external DLLUtilName;
function  X509_NAME_add_entry(name:PX509_NAME; ne:PX509_NAME_ENTRY; loc:cint; _set:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_add_entry_by_OBJ(name:PX509_NAME; obj:PASN1_OBJECT; _type:cint; bytes:pbyte; len:cint; 
               loc:cint; _set:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_add_entry_by_NID(name:PX509_NAME; nid:cint; _type:cint; bytes:pbyte; len:cint; 
               loc:cint; _set:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_create_by_txt(ne:PPX509_NAME_ENTRY; field:pbyte; _type:cint; bytes:pbyte; len:cint):PX509_NAME_ENTRY;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_create_by_NID(ne:PPX509_NAME_ENTRY; nid:cint; _type:cint; bytes:pbyte; len:cint):PX509_NAME_ENTRY;cdecl; external DLLUtilName;
function  X509_NAME_add_entry_by_txt(name:PX509_NAME; field:pbyte; _type:cint; bytes:pbyte; len:cint; 
               loc:cint; _set:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_create_by_OBJ(ne:PPX509_NAME_ENTRY; obj:PASN1_OBJECT; _type:cint; bytes:pbyte; len:cint):PX509_NAME_ENTRY;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_set_object(ne:PX509_NAME_ENTRY; obj:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_set_data(ne:PX509_NAME_ENTRY; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_get_object(ne:PX509_NAME_ENTRY):PASN1_OBJECT;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_get_data(ne:PX509_NAME_ENTRY):PASN1_STRING;cdecl; external DLLUtilName;
function  X509_NAME_ENTRY_set(ne:PX509_NAME_ENTRY):cint;cdecl; external DLLUtilName;
function  X509_NAME_get0_der(nm:PX509_NAME; pder:Ppbyte; pderlen:Psize_t):cint;cdecl; external DLLUtilName;
function  X509v3_get_ext_count(x:Pstack_st_X509_EXTENSION):cint;cdecl; external DLLUtilName;
function  X509v3_get_ext_by_NID(x:Pstack_st_X509_EXTENSION; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509v3_get_ext_by_OBJ(x:Pstack_st_X509_EXTENSION; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509v3_get_ext_by_critical(x:Pstack_st_X509_EXTENSION; crit:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509v3_get_ext(x:Pstack_st_X509_EXTENSION; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509v3_delete_ext(x:Pstack_st_X509_EXTENSION; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_get_ext_count(x:PX509):cint;cdecl; external DLLUtilName;
function  X509_get_ext_by_NID(x:PX509; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_get_ext_by_OBJ(x:PX509; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_get_ext_by_critical(x:PX509; crit:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_get_ext(x:PX509; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_delete_ext(x:PX509; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_add_ext(x:PX509; ex:PX509_EXTENSION; loc:cint):cint;cdecl; external DLLUtilName;
function  X509_get_ext_d2i(x:PX509; nid:cint; crit:pcint; idx:pcint):pointer;cdecl; external DLLUtilName;
function  X509_add1_ext_i2d(x:PX509; nid:cint; value:pointer; crit:cint; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_CRL_get_ext_count(x:PX509_CRL):cint;cdecl; external DLLUtilName;
function  X509_CRL_get_ext_by_NID(x:PX509_CRL; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_CRL_get_ext_by_OBJ(x:PX509_CRL; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_CRL_get_ext_by_critical(x:PX509_CRL; crit:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_CRL_get_ext(x:PX509_CRL; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_CRL_delete_ext(x:PX509_CRL; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_CRL_add_ext(x:PX509_CRL; ex:PX509_EXTENSION; loc:cint):cint;cdecl; external DLLUtilName;
function  X509_CRL_get_ext_d2i(x:PX509_CRL; nid:cint; crit:pcint; idx:pcint):pointer;cdecl; external DLLUtilName;
function  X509_CRL_add1_ext_i2d(x:PX509_CRL; nid:cint; value:pointer; crit:cint; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get_ext_count(x:PX509_REVOKED):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get_ext_by_NID(x:PX509_REVOKED; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get_ext_by_OBJ(x:PX509_REVOKED; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get_ext_by_critical(x:PX509_REVOKED; crit:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get_ext(x:PX509_REVOKED; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_REVOKED_delete_ext(x:PX509_REVOKED; loc:cint):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_REVOKED_add_ext(x:PX509_REVOKED; ex:PX509_EXTENSION; loc:cint):cint;cdecl; external DLLUtilName;
function  X509_REVOKED_get_ext_d2i(x:PX509_REVOKED; nid:cint; crit:pcint; idx:pcint):pointer;cdecl; external DLLUtilName;
function  X509_REVOKED_add1_ext_i2d(x:PX509_REVOKED; nid:cint; value:pointer; crit:cint; flags:culong):cint;cdecl; external DLLUtilName;
function  X509_EXTENSION_create_by_NID(ex:PPX509_EXTENSION; nid:cint; crit:cint; data:PASN1_OCTET_STRING):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_EXTENSION_create_by_OBJ(ex:PPX509_EXTENSION; obj:PASN1_OBJECT; crit:cint; data:PASN1_OCTET_STRING):PX509_EXTENSION;cdecl; external DLLUtilName;
function  X509_EXTENSION_set_object(ex:PX509_EXTENSION; obj:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_EXTENSION_set_critical(ex:PX509_EXTENSION; crit:cint):cint;cdecl; external DLLUtilName;
function  X509_EXTENSION_set_data(ex:PX509_EXTENSION; data:PASN1_OCTET_STRING):cint;cdecl; external DLLUtilName;
function  X509_EXTENSION_get_object(ex:PX509_EXTENSION):PASN1_OBJECT;cdecl; external DLLUtilName;
function  X509_EXTENSION_get_data(ne:PX509_EXTENSION):PASN1_OCTET_STRING;cdecl; external DLLUtilName;
function  X509_EXTENSION_get_critical(ex:PX509_EXTENSION):cint;cdecl; external DLLUtilName;
function  X509at_get_attr_count(x:Pstack_st_X509_ATTRIBUTE):cint;cdecl; external DLLUtilName;
function  X509at_get_attr_by_NID(x:Pstack_st_X509_ATTRIBUTE; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509at_get_attr_by_OBJ(sk:Pstack_st_X509_ATTRIBUTE; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  X509at_get_attr(x:Pstack_st_X509_ATTRIBUTE; loc:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509at_delete_attr(x:Pstack_st_X509_ATTRIBUTE; loc:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509at_get0_data_by_OBJ(x:Pstack_st_X509_ATTRIBUTE; obj:PASN1_OBJECT; lastpos:cint; _type:cint):pointer;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_create_by_NID(attr:PPX509_ATTRIBUTE; nid:cint; atrtype:cint; data:pointer; len:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_create_by_OBJ(attr:PPX509_ATTRIBUTE; obj:PASN1_OBJECT; atrtype:cint; data:pointer; len:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_create_by_txt(attr:PPX509_ATTRIBUTE; atrname:pbyte; _type:cint; bytes:pbyte; len:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_set1_object(attr:PX509_ATTRIBUTE; obj:PASN1_OBJECT):cint;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_set1_data(attr:PX509_ATTRIBUTE; attrtype:cint; data:pointer; len:cint):cint;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_get0_data(attr:PX509_ATTRIBUTE; idx:cint; atrtype:cint; data:pointer):pointer;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_count(attr:PX509_ATTRIBUTE):cint;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_get0_object(attr:PX509_ATTRIBUTE):PASN1_OBJECT;cdecl; external DLLUtilName;
function  X509_ATTRIBUTE_get0_type(attr:PX509_ATTRIBUTE; idx:cint):PASN1_TYPE;cdecl; external DLLUtilName;
function  EVP_PKEY_get_attr_count(key:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_get_attr_by_NID(key:PEVP_PKEY; nid:cint; lastpos:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_get_attr_by_OBJ(key:PEVP_PKEY; obj:PASN1_OBJECT; lastpos:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_get_attr(key:PEVP_PKEY; loc:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  EVP_PKEY_delete_attr(key:PEVP_PKEY; loc:cint):PX509_ATTRIBUTE;cdecl; external DLLUtilName;
function  EVP_PKEY_add1_attr(key:PEVP_PKEY; attr:PX509_ATTRIBUTE):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_add1_attr_by_OBJ(key:PEVP_PKEY; obj:PASN1_OBJECT; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_add1_attr_by_NID(key:PEVP_PKEY; nid:cint; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  EVP_PKEY_add1_attr_by_txt(key:PEVP_PKEY; attrname:pbyte; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_verify_cert(ctx:PX509_STORE_CTX):cint;cdecl; external DLLUtilName;
function  X509_find_by_issuer_and_serial(sk:Pstack_st_X509; name:PX509_NAME; serial:PASN1_INTEGER):PX509;cdecl; external DLLUtilName;
function  X509_find_by_subject(sk:Pstack_st_X509; name:PX509_NAME):PX509;cdecl; external DLLUtilName;
function  PBEPARAM_new:PPBEPARAM;cdecl; external DLLUtilName;
procedure PBEPARAM_free(a:PPBEPARAM);cdecl; external DLLUtilName;
function  d2i_PBEPARAM(a:PPPBEPARAM;_in:Ppbyte; len:clong):PPBEPARAM;cdecl; external DLLUtilName;
function  i2d_PBEPARAM(a:PPBEPARAM;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PBE2PARAM_new:PPBE2PARAM;cdecl; external DLLUtilName;
procedure PBE2PARAM_free(a:PPBE2PARAM);cdecl; external DLLUtilName;
function  d2i_PBE2PARAM(a:PPPBE2PARAM;_in:Ppbyte; len:clong):PPBE2PARAM;cdecl; external DLLUtilName;
function  i2d_PBE2PARAM(a:PPBE2PARAM;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PBKDF2PARAM_new:PPBKDF2PARAM;cdecl; external DLLUtilName;
procedure PBKDF2PARAM_free(a:PPBKDF2PARAM);cdecl; external DLLUtilName;
function  d2i_PBKDF2PARAM(a:PPPBKDF2PARAM;_in:Ppbyte; len:clong):PPBKDF2PARAM;cdecl; external DLLUtilName;
function  i2d_PBKDF2PARAM(a:PPBKDF2PARAM;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  PKCS5_pbe_set0_algor(algor:PX509_ALGOR; alg:cint; iter:cint; salt:pbyte; saltlen:cint):cint;cdecl; external DLLUtilName;
function  PKCS5_pbe_set(alg:cint; iter:cint; salt:pbyte; saltlen:cint):PX509_ALGOR;cdecl; external DLLUtilName;
function  PKCS5_pbe2_set(cipher:PEVP_CIPHER; iter:cint; salt:pbyte; saltlen:cint):PX509_ALGOR;cdecl; external DLLUtilName;
function  PKCS5_pbe2_set_iv(cipher:PEVP_CIPHER; iter:cint; salt:pbyte; saltlen:cint; aiv:pbyte; 
               prf_nid:cint):PX509_ALGOR;cdecl; external DLLUtilName;
function  PKCS5_pbe2_set_scrypt(cipher:PEVP_CIPHER; salt:pbyte; saltlen:cint; aiv:pbyte; N:uint64; 
               r:uint64; p:uint64):PX509_ALGOR;cdecl; external DLLUtilName;
function  PKCS5_pbkdf2_set(iter:cint; salt:pbyte; saltlen:cint; prf_nid:cint; keylen:cint):PX509_ALGOR;cdecl; external DLLUtilName;
function  PKCS8_PRIV_KEY_INFO_new:PPKCS8_PRIV_KEY_INFO;cdecl; external DLLUtilName;
procedure PKCS8_PRIV_KEY_INFO_free(a:PPKCS8_PRIV_KEY_INFO);cdecl; external DLLUtilName;
function  d2i_PKCS8_PRIV_KEY_INFO(a:PPPKCS8_PRIV_KEY_INFO;_in:Ppbyte; len:clong):PPKCS8_PRIV_KEY_INFO;cdecl; external DLLUtilName;
function  i2d_PKCS8_PRIV_KEY_INFO(a:PPKCS8_PRIV_KEY_INFO;_out:Ppbyte):cint;cdecl; external DLLUtilName;

function  EVP_PKCS82PKEY(p8:PPKCS8_PRIV_KEY_INFO):PEVP_PKEY;cdecl; external DLLUtilName;
function  EVP_PKEY2PKCS8(pkey:PEVP_PKEY):PPKCS8_PRIV_KEY_INFO;cdecl; external DLLUtilName;
function  PKCS8_pkey_set0(priv:PPKCS8_PRIV_KEY_INFO; aobj:PASN1_OBJECT; version:cint; ptype:cint; pval:pointer; 
               penc:pbyte; penclen:cint):cint;cdecl; external DLLUtilName;
function  PKCS8_pkey_get0(ppkalg:PPASN1_OBJECT; pk:Ppbyte; ppklen:pcint; pa:PPX509_ALGOR; p8:PPKCS8_PRIV_KEY_INFO):cint;cdecl; external DLLUtilName;
function  PKCS8_pkey_get0_attrs(p8:PPKCS8_PRIV_KEY_INFO):Pstack_st_X509_ATTRIBUTE;cdecl; external DLLUtilName;
function  PKCS8_pkey_add1_attr_by_NID(p8:PPKCS8_PRIV_KEY_INFO; nid:cint; _type:cint; bytes:pbyte; len:cint):cint;cdecl; external DLLUtilName;
function  X509_PUBKEY_set0_param(pub:PX509_PUBKEY; aobj:PASN1_OBJECT; ptype:cint; pval:pointer; penc:pbyte; 
               penclen:cint):cint;cdecl; external DLLUtilName;
function  X509_PUBKEY_get0_param(ppkalg:PPASN1_OBJECT; pk:Ppbyte; ppklen:pcint; pa:PPX509_ALGOR; pub:PX509_PUBKEY):cint;cdecl; external DLLUtilName;
function  X509_check_trust(x:PX509; id:cint; flags:cint):cint;cdecl; external DLLUtilName;
function  X509_TRUST_get_count:cint;cdecl; external DLLUtilName;
function  X509_TRUST_get0(idx:cint):PX509_TRUST;cdecl; external DLLUtilName;
function  X509_TRUST_get_by_id(id:cint):cint;cdecl; external DLLUtilName;

type
 TX509_ck_cb=function  (para1:PX509_TRUST; para2:PX509; para3:cint):cint;cdecl;

function  X509_TRUST_add(id:cint; flags:cint; ck:TX509_ck_cb; name:pbyte; arg1:cint;
               arg2:pointer):cint;cdecl; external DLLUtilName;
procedure X509_TRUST_cleanup;cdecl; external DLLUtilName;
function  X509_TRUST_get_flags(xp:PX509_TRUST):cint;cdecl; external DLLUtilName;
function  X509_TRUST_get0_name(xp:PX509_TRUST):pbyte;cdecl; external DLLUtilName;
function  X509_TRUST_get_trust(xp:PX509_TRUST):cint;cdecl; external DLLUtilName;
function  ERR_load_X509_strings:cint;cdecl; external DLLUtilName;
    const
      X509_F_ADD_CERT_DIR = 100;      
      X509_F_BUILD_CHAIN = 106;      
      X509_F_BY_FILE_CTRL = 101;      
      X509_F_CHECK_NAME_CONSTRAINTS = 149;      
      X509_F_CHECK_POLICY = 145;      
      X509_F_DANE_I2D = 107;      
      X509_F_DIR_CTRL = 102;      
      X509_F_GET_CERT_BY_SUBJECT = 103;      
      X509_F_NETSCAPE_SPKI_B64_DECODE = 129;      
      X509_F_NETSCAPE_SPKI_B64_ENCODE = 130;      
      X509_F_X509AT_ADD1_ATTR = 135;      
      X509_F_X509V3_ADD_EXT = 104;      
      X509_F_X509_ATTRIBUTE_CREATE_BY_NID = 136;      
      X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ = 137;      
      X509_F_X509_ATTRIBUTE_CREATE_BY_TXT = 140;      
      X509_F_X509_ATTRIBUTE_GET0_DATA = 139;      
      X509_F_X509_ATTRIBUTE_SET1_DATA = 138;      
      X509_F_X509_CHECK_PRIVATE_KEY = 128;      
      X509_F_X509_CRL_DIFF = 105;      
      X509_F_X509_CRL_PRINT_FP = 147;      
      X509_F_X509_EXTENSION_CREATE_BY_NID = 108;      
      X509_F_X509_EXTENSION_CREATE_BY_OBJ = 109;      
      X509_F_X509_GET_PUBKEY_PARAMETERS = 110;      
      X509_F_X509_LOAD_CERT_CRL_FILE = 132;      
      X509_F_X509_LOAD_CERT_FILE = 111;      
      X509_F_X509_LOAD_CRL_FILE = 112;      
      X509_F_X509_NAME_ADD_ENTRY = 113;      
      X509_F_X509_NAME_ENTRY_CREATE_BY_NID = 114;      
      X509_F_X509_NAME_ENTRY_CREATE_BY_TXT = 131;      
      X509_F_X509_NAME_ENTRY_SET_OBJECT = 115;      
      X509_F_X509_NAME_ONELINE = 116;      
      X509_F_X509_NAME_PRINT = 117;      
      X509_F_X509_OBJECT_NEW = 150;      
      X509_F_X509_PRINT_EX_FP = 118;      
      X509_F_X509_PUBKEY_DECODE = 148;      
      X509_F_X509_PUBKEY_GET0 = 119;      
      X509_F_X509_PUBKEY_SET = 120;      
      X509_F_X509_REQ_CHECK_PRIVATE_KEY = 144;      
      X509_F_X509_REQ_PRINT_EX = 121;      
      X509_F_X509_REQ_PRINT_FP = 122;      
      X509_F_X509_REQ_TO_X509 = 123;      
      X509_F_X509_STORE_ADD_CERT = 124;      
      X509_F_X509_STORE_ADD_CRL = 125;      
      X509_F_X509_STORE_CTX_GET1_ISSUER = 146;      
      X509_F_X509_STORE_CTX_INIT = 143;      
      X509_F_X509_STORE_CTX_NEW = 142;      
      X509_F_X509_STORE_CTX_PURPOSE_INHERIT = 134;      
      X509_F_X509_TO_X509_REQ = 126;      
      X509_F_X509_TRUST_ADD = 133;      
      X509_F_X509_TRUST_SET = 141;      
      X509_F_X509_VERIFY_CERT = 127;      
      X509_R_AKID_MISMATCH = 110;      
      X509_R_BAD_SELECTOR = 133;      
      X509_R_BAD_X509_FILETYPE = 100;      
      X509_R_BASE64_DECODE_ERROR = 118;      
      X509_R_CANT_CHECK_DH_KEY = 114;      
      X509_R_CERT_ALREADY_IN_HASH_TABLE = 101;      
      X509_R_CRL_ALREADY_DELTA = 127;      
      X509_R_CRL_VERIFY_FAILURE = 131;      
      X509_R_IDP_MISMATCH = 128;      
      X509_R_INVALID_DIRECTORY = 113;      
      X509_R_INVALID_FIELD_NAME = 119;      
      X509_R_INVALID_TRUST = 123;      
      X509_R_ISSUER_MISMATCH = 129;      
      X509_R_KEY_TYPE_MISMATCH = 115;      
      X509_R_KEY_VALUES_MISMATCH = 116;      
      X509_R_LOADING_CERT_DIR = 103;      
      X509_R_LOADING_DEFAULTS = 104;      
      X509_R_METHOD_NOT_SUPPORTED = 124;      
      X509_R_NAME_TOO_LONG = 134;      
      X509_R_NEWER_CRL_NOT_NEWER = 132;      
      X509_R_NO_CERT_SET_FOR_US_TO_VERIFY = 105;      
      X509_R_NO_CRL_NUMBER = 130;      
      X509_R_PUBLIC_KEY_DECODE_ERROR = 125;      
      X509_R_PUBLIC_KEY_ENCODE_ERROR = 126;      
      X509_R_SHOULD_RETRY = 106;      
      X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107;      
      X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY = 108;      
      X509_R_UNKNOWN_KEY_TYPE = 117;      
      X509_R_UNKNOWN_NID = 109;      
      X509_R_UNKNOWN_PURPOSE_ID = 121;      
      X509_R_UNKNOWN_TRUST_ID = 120;      
      X509_R_UNSUPPORTED_ALGORITHM = 111;      
      X509_R_WRONG_LOOKUP_TYPE = 112;      
      X509_R_WRONG_TYPE = 122;      
{$define HEADER_PEM_H}    
      PEM_BUFSIZE = 1024;
      PEM_TYPE_ENCRYPTED = 10;      
      PEM_TYPE_MIC_ONLY = 20;      
      PEM_TYPE_MIC_CLEAR = 30;      
      PEM_TYPE_CLEAR = 40;      
    type
      Ppem_recip= ^Tpem_recip_st;
      Tpem_recip_st = record
          name : pbyte;
          dn : PX509_NAME;
          cipher : cint;
          key_enc : cint;
        end;
      TPEM_USER = Tpem_recip_st;
      PPEM_USER = ^TPEM_USER;

      Ppem_ctx= ^Tpem_ctx_st;
      Tpem_ctx_st = record
          _type : cint;
          proc_type : record
              version : cint;
              mode : cint;
            end;
          domain : pbyte;
          DEK_info : record
              cipher : cint;
            end;
          originator : PPEM_USER;
          num_recipient : cint;
          recipient : ^PPEM_USER;
          md : PEVP_MD;
          md_enc : cint;
          md_len : cint;
          md_data : pbyte;
          dec : PEVP_CIPHER;
          key_len : cint;
          key : pbyte;
          data_enc : cint;
          data_len : cint;
          data : pbyte;
        end;

      Ppem_password_cb = ^Tpem_password_cb;
      Tpem_password_cb = record end;

function  PEM_get_EVP_CIPHER_INFO(header:pbyte; cipher:PEVP_CIPHER_INFO):cint;cdecl; external DLLUtilName;
function  PEM_do_header(cipher:PEVP_CIPHER_INFO; data:pbyte; len:pclong; callback:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_read_bio(bp:PBIO; name:Ppbyte; header:Ppbyte; data:Ppbyte; len:pclong):cint;cdecl; external DLLUtilName;
function  PEM_write_bio(bp:PBIO; name:pbyte; hdr:pbyte; data:pbyte; len:clong):cint;cdecl; external DLLUtilName;
function  PEM_bytes_read_bio(pdata:Ppbyte; plen:pclong; pnm:Ppbyte; name:pbyte; bp:PBIO; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_ASN1_read_bio(d2i:Pd2i_of_void; name:pbyte; bp:PBIO; x:Ppointer; cb:Ppem_password_cb; 
               u:pointer):pointer;cdecl; external DLLUtilName;
function  PEM_ASN1_write_bio(i2d:Pi2d_of_void; name:pbyte; bp:PBIO; x:pointer; enc:PEVP_CIPHER; 
               kstr:pbyte; klen:cint; cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_X509_INFO_write_bio(bp:PBIO; xi:PX509_INFO; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
               cd:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  PEM_read(fp:PFILE; name:Ppbyte; header:Ppbyte; data:Ppbyte; len:pclong):cint;cdecl; external DLLUtilName;
//function  PEM_write(fp:PFILE; name:pbyte; hdr:pbyte; data:pbyte; len:clong):cint;cdecl; external DLLUtilName;
//function  PEM_ASN1_read(d2i:Pd2i_of_void; name:pbyte; fp:PFILE; x:Ppointer; cb:Ppem_password_cb; 
//               u:pointer):pointer;cdecl; external DLLUtilName;
//function  PEM_ASN1_write(i2d:Pi2d_of_void; name:pbyte; fp:PFILE; x:pointer; enc:PEVP_CIPHER; 
//               kstr:pbyte; klen:cint; callback:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_SignInit(ctx:PEVP_MD_CTX; _type:PEVP_MD):cint;cdecl; external DLLUtilName;
function  PEM_SignUpdate(ctx:PEVP_MD_CTX; d:pbyte; cnt:cuint):cint;cdecl; external DLLUtilName;
function  PEM_SignFinal(ctx:PEVP_MD_CTX; sigret:pbyte; siglen:pcuint; pkey:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  PEM_def_callback(buf:pbyte; num:cint; w:cint; key:pointer):cint;cdecl; external DLLUtilName;
procedure PEM_proc_type(buf:pbyte; _type:cint);cdecl; external DLLUtilName;
procedure PEM_dek_info(buf:pbyte; _type:pbyte; len:cint; str:pbyte);cdecl; external DLLUtilName;
function  PEM_read_bio_X509(bp:PBIO; x:PPX509; cb:Ppem_password_cb; u:pointer):PX509;cdecl; external DLLUtilName;
//function  PEM_read_X509(fp:PFILE; x:PPX509; cb:Ppem_password_cb; u:pointer):PX509;cdecl; external DLLUtilName;
function  PEM_write_bio_X509(bp:PBIO; x:PX509):cint;cdecl; external DLLUtilName;
//function  PEM_write_X509(fp:PFILE; x:PX509):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_X509_AUX(bp:PBIO; x:PPX509; cb:Ppem_password_cb; u:pointer):PX509;cdecl; external DLLUtilName;
//function  PEM_read_X509_AUX(fp:PFILE; x:PPX509; cb:Ppem_password_cb; u:pointer):PX509;cdecl; external DLLUtilName;
function  PEM_write_bio_X509_AUX(bp:PBIO; x:PX509):cint;cdecl; external DLLUtilName;
//function  PEM_write_X509_AUX(fp:PFILE; x:PX509):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_X509_REQ(bp:PBIO; x:PPX509_REQ; cb:Ppem_password_cb; u:pointer):PX509_REQ;cdecl; external DLLUtilName;
//function  PEM_read_X509_REQ(fp:PFILE; x:PPX509_REQ; cb:Ppem_password_cb; u:pointer):PX509_REQ;cdecl; external DLLUtilName;
function  PEM_write_bio_X509_REQ(bp:PBIO; x:PX509_REQ):cint;cdecl; external DLLUtilName;
//function  PEM_write_X509_REQ(fp:PFILE; x:PX509_REQ):cint;cdecl; external DLLUtilName;
function  PEM_write_bio_X509_REQ_NEW(bp:PBIO; x:PX509_REQ):cint;cdecl; external DLLUtilName;
//function  PEM_write_X509_REQ_NEW(fp:PFILE; x:PX509_REQ):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_X509_CRL(bp:PBIO; x:PPX509_CRL; cb:Ppem_password_cb; u:pointer):PX509_CRL;cdecl; external DLLUtilName;
//function  PEM_read_X509_CRL(fp:PFILE; x:PPX509_CRL; cb:Ppem_password_cb; u:pointer):PX509_CRL;cdecl; external DLLUtilName;
function  PEM_write_bio_X509_CRL(bp:PBIO; x:PX509_CRL):cint;cdecl; external DLLUtilName;
//function  PEM_write_X509_CRL(fp:PFILE; x:PX509_CRL):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_PKCS7(bp:PBIO; x:PPPKCS7; cb:Ppem_password_cb; u:pointer):PPKCS7;cdecl; external DLLUtilName;
//function  PEM_read_PKCS7(fp:PFILE; x:PPPKCS7; cb:Ppem_password_cb; u:pointer):PPKCS7;cdecl; external DLLUtilName;
function  PEM_write_bio_PKCS7(bp:PBIO; x:PPKCS7):cint;cdecl; external DLLUtilName;
//function  PEM_write_PKCS7(fp:PFILE; x:PPKCS7):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_NETSCAPE_CERT_SEQUENCE(bp:PBIO; x:PPNETSCAPE_CERT_SEQUENCE; cb:Ppem_password_cb; u:pointer):PNETSCAPE_CERT_SEQUENCE;cdecl; external DLLUtilName;
//function  PEM_read_NETSCAPE_CERT_SEQUENCE(fp:PFILE; x:PPNETSCAPE_CERT_SEQUENCE; cb:Ppem_password_cb; u:pointer):PNETSCAPE_CERT_SEQUENCE;cdecl; external DLLUtilName;
function  PEM_write_bio_NETSCAPE_CERT_SEQUENCE(bp:PBIO; x:PNETSCAPE_CERT_SEQUENCE):cint;cdecl; external DLLUtilName;
//function  PEM_write_NETSCAPE_CERT_SEQUENCE(fp:PFILE; x:PNETSCAPE_CERT_SEQUENCE):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_PKCS8(bp:PBIO; x:PPX509_SIG; cb:Ppem_password_cb; u:pointer):PX509_SIG;cdecl; external DLLUtilName;
//function  PEM_read_PKCS8(fp:PFILE; x:PPX509_SIG; cb:Ppem_password_cb; u:pointer):PX509_SIG;cdecl; external DLLUtilName;
function  PEM_write_bio_PKCS8(bp:PBIO; x:PX509_SIG):cint;cdecl; external DLLUtilName;
//function  PEM_write_PKCS8(fp:PFILE; x:PX509_SIG):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_PKCS8_PRIV_KEY_INFO(bp:PBIO; x:PPPKCS8_PRIV_KEY_INFO; cb:Ppem_password_cb; u:pointer):PPKCS8_PRIV_KEY_INFO;cdecl; external DLLUtilName;
//function  PEM_read_PKCS8_PRIV_KEY_INFO(fp:PFILE; x:PPPKCS8_PRIV_KEY_INFO; cb:Ppem_password_cb; u:pointer):PPKCS8_PRIV_KEY_INFO;cdecl; external DLLUtilName;
function  PEM_write_bio_PKCS8_PRIV_KEY_INFO(bp:PBIO; x:PPKCS8_PRIV_KEY_INFO):cint;cdecl; external DLLUtilName;
//function  PEM_write_PKCS8_PRIV_KEY_INFO(fp:PFILE; x:PPKCS8_PRIV_KEY_INFO):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_RSAPrivateKey(bp:PBIO; x:PPRSA; cb:Ppem_password_cb; u:pointer):PRSA;cdecl; external DLLUtilName;
//function  PEM_read_RSAPrivateKey(fp:PFILE; x:PPRSA; cb:Ppem_password_cb; u:pointer):PRSA;cdecl; external DLLUtilName;
function  PEM_write_bio_RSAPrivateKey(bp:PBIO; x:PRSA; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  PEM_write_RSAPrivateKey(fp:PFILE; x:PRSA; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
//               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_RSAPublicKey(bp:PBIO; x:PPRSA; cb:Ppem_password_cb; u:pointer):PRSA;cdecl; external DLLUtilName;
//function  PEM_read_RSAPublicKey(fp:PFILE; x:PPRSA; cb:Ppem_password_cb; u:pointer):PRSA;cdecl; external DLLUtilName;
function  PEM_write_bio_RSAPublicKey(bp:PBIO; x:PRSA):cint;cdecl; external DLLUtilName;
//function  PEM_write_RSAPublicKey(fp:PFILE; x:PRSA):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_RSA_PUBKEY(bp:PBIO; x:PPRSA; cb:Ppem_password_cb; u:pointer):PRSA;cdecl; external DLLUtilName;
//function  PEM_read_RSA_PUBKEY(fp:PFILE; x:PPRSA; cb:Ppem_password_cb; u:pointer):PRSA;cdecl; external DLLUtilName;
function  PEM_write_bio_RSA_PUBKEY(bp:PBIO; x:PRSA):cint;cdecl; external DLLUtilName;
//function  PEM_write_RSA_PUBKEY(fp:PFILE; x:PRSA):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_DSAPrivateKey(bp:PBIO; x:PPDSA; cb:Ppem_password_cb; u:pointer):PDSA;cdecl; external DLLUtilName;
//function  PEM_read_DSAPrivateKey(fp:PFILE; x:PPDSA; cb:Ppem_password_cb; u:pointer):PDSA;cdecl; external DLLUtilName;
function  PEM_write_bio_DSAPrivateKey(bp:PBIO; x:PDSA; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  PEM_write_DSAPrivateKey(fp:PFILE; x:PDSA; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
//               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_DSA_PUBKEY(bp:PBIO; x:PPDSA; cb:Ppem_password_cb; u:pointer):PDSA;cdecl; external DLLUtilName;
//function  PEM_read_DSA_PUBKEY(fp:PFILE; x:PPDSA; cb:Ppem_password_cb; u:pointer):PDSA;cdecl; external DLLUtilName;
function  PEM_write_bio_DSA_PUBKEY(bp:PBIO; x:PDSA):cint;cdecl; external DLLUtilName;
//function  PEM_write_DSA_PUBKEY(fp:PFILE; x:PDSA):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_DSAparams(bp:PBIO; x:PPDSA; cb:Ppem_password_cb; u:pointer):PDSA;cdecl; external DLLUtilName;
//function  PEM_read_DSAparams(fp:PFILE; x:PPDSA; cb:Ppem_password_cb; u:pointer):PDSA;cdecl; external DLLUtilName;
function  PEM_write_bio_DSAparams(bp:PBIO; x:PDSA):cint;cdecl; external DLLUtilName;
//function  PEM_write_DSAparams(fp:PFILE; x:PDSA):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_ECPKParameters(bp:PBIO; x:PPEC_GROUP; cb:Ppem_password_cb; u:pointer):PEC_GROUP;cdecl; external DLLUtilName;
//function  PEM_read_ECPKParameters(fp:PFILE; x:PPEC_GROUP; cb:Ppem_password_cb; u:pointer):PEC_GROUP;cdecl; external DLLUtilName;
function  PEM_write_bio_ECPKParameters(bp:PBIO; x:PEC_GROUP):cint;cdecl; external DLLUtilName;
//function  PEM_write_ECPKParameters(fp:PFILE; x:PEC_GROUP):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_ECPrivateKey(bp:PBIO; x:PPEC_KEY; cb:Ppem_password_cb; u:pointer):PEC_KEY;cdecl; external DLLUtilName;
//function  PEM_read_ECPrivateKey(fp:PFILE; x:PPEC_KEY; cb:Ppem_password_cb; u:pointer):PEC_KEY;cdecl; external DLLUtilName;
function  PEM_write_bio_ECPrivateKey(bp:PBIO; x:PEC_KEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  PEM_write_ECPrivateKey(fp:PFILE; x:PEC_KEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
//               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_EC_PUBKEY(bp:PBIO; x:PPEC_KEY; cb:Ppem_password_cb; u:pointer):PEC_KEY;cdecl; external DLLUtilName;
//function  PEM_read_EC_PUBKEY(fp:PFILE; x:PPEC_KEY; cb:Ppem_password_cb; u:pointer):PEC_KEY;cdecl; external DLLUtilName;
function  PEM_write_bio_EC_PUBKEY(bp:PBIO; x:PEC_KEY):cint;cdecl; external DLLUtilName;
//function  PEM_write_EC_PUBKEY(fp:PFILE; x:PEC_KEY):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_DHparams(bp:PBIO; x:PPDH; cb:Ppem_password_cb; u:pointer):PDH;cdecl; external DLLUtilName;
//function  PEM_read_DHparams(fp:PFILE; x:PPDH; cb:Ppem_password_cb; u:pointer):PDH;cdecl; external DLLUtilName;
function  PEM_write_bio_DHparams(bp:PBIO; x:PDH):cint;cdecl; external DLLUtilName;
//function  PEM_write_DHparams(fp:PFILE; x:PDH):cint;cdecl; external DLLUtilName;
function  PEM_write_bio_DHxparams(bp:PBIO; x:PDH):cint;cdecl; external DLLUtilName;
//function  PEM_write_DHxparams(fp:PFILE; x:PDH):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_PrivateKey(bp:PBIO; x:PPEVP_PKEY; cb:Ppem_password_cb; u:pointer):PEVP_PKEY;cdecl; external DLLUtilName;
//function  PEM_read_PrivateKey(fp:PFILE; x:PPEVP_PKEY; cb:Ppem_password_cb; u:pointer):PEVP_PKEY;cdecl; external DLLUtilName;
function  PEM_write_bio_PrivateKey(bp:PBIO; x:PEVP_PKEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  PEM_write_PrivateKey(fp:PFILE; x:PEVP_PKEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
//               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_PUBKEY(bp:PBIO; x:PPEVP_PKEY; cb:Ppem_password_cb; u:pointer):PEVP_PKEY;cdecl; external DLLUtilName;
//function  PEM_read_PUBKEY(fp:PFILE; x:PPEVP_PKEY; cb:Ppem_password_cb; u:pointer):PEVP_PKEY;cdecl; external DLLUtilName;
function  PEM_write_bio_PUBKEY(bp:PBIO; x:PEVP_PKEY):cint;cdecl; external DLLUtilName;
//function  PEM_write_PUBKEY(fp:PFILE; x:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  PEM_write_bio_PrivateKey_traditional(bp:PBIO; x:PEVP_PKEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_write_bio_PKCS8PrivateKey_nid(bp:PBIO; x:PEVP_PKEY; nid:cint; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_write_bio_PKCS8PrivateKey(para1:PBIO; para2:PEVP_PKEY; para3:PEVP_CIPHER; para4:pbyte; para5:cint; 
               para6:Ppem_password_cb; para7:pointer):cint;cdecl; external DLLUtilName;
function  i2d_PKCS8PrivateKey_bio(bp:PBIO; x:PEVP_PKEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  i2d_PKCS8PrivateKey_nid_bio(bp:PBIO; x:PEVP_PKEY; nid:cint; kstr:pbyte; klen:cint; 
               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  d2i_PKCS8PrivateKey_bio(bp:PBIO; x:PPEVP_PKEY; cb:Ppem_password_cb; u:pointer):PEVP_PKEY;cdecl; external DLLUtilName;
//function  i2d_PKCS8PrivateKey_fp(fp:PFILE; x:PEVP_PKEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
//               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  i2d_PKCS8PrivateKey_nid_fp(fp:PFILE; x:PEVP_PKEY; nid:cint; kstr:pbyte; klen:cint; 
//               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  PEM_write_PKCS8PrivateKey_nid(fp:PFILE; x:PEVP_PKEY; nid:cint; kstr:pbyte; klen:cint; 
//               cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
//function  d2i_PKCS8PrivateKey_fp(fp:PFILE; x:PPEVP_PKEY; cb:Ppem_password_cb; u:pointer):PEVP_PKEY;cdecl; external DLLUtilName;
//function  PEM_write_PKCS8PrivateKey(fp:PFILE; x:PEVP_PKEY; enc:PEVP_CIPHER; kstr:pbyte; klen:cint; 
//               cd:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  PEM_read_bio_Parameters(bp:PBIO; x:PPEVP_PKEY):PEVP_PKEY;cdecl; external DLLUtilName;
function  PEM_write_bio_Parameters(bp:PBIO; x:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  b2i_PrivateKey(_in:Ppbyte; length:clong):PEVP_PKEY;cdecl; external DLLUtilName;
function  b2i_PublicKey(_in:Ppbyte; length:clong):PEVP_PKEY;cdecl; external DLLUtilName;
function  b2i_PrivateKey_bio(_in:PBIO):PEVP_PKEY;cdecl; external DLLUtilName;
function  b2i_PublicKey_bio(_in:PBIO):PEVP_PKEY;cdecl; external DLLUtilName;
function  i2b_PrivateKey_bio(_out:PBIO; pk:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  i2b_PublicKey_bio(_out:PBIO; pk:PEVP_PKEY):cint;cdecl; external DLLUtilName;
function  b2i_PVK_bio(_in:PBIO; cb:Ppem_password_cb; u:pointer):PEVP_PKEY;cdecl; external DLLUtilName;
function  i2b_PVK_bio(_out:PBIO; pk:PEVP_PKEY; enclevel:cint; cb:Ppem_password_cb; u:pointer):cint;cdecl; external DLLUtilName;
function  ERR_load_PEM_strings:cint;cdecl; external DLLUtilName;
    const
      PEM_F_B2I_DSS = 127;      
      PEM_F_B2I_PVK_BIO = 128;      
      PEM_F_B2I_RSA = 129;      
      PEM_F_CHECK_BITLEN_DSA = 130;      
      PEM_F_CHECK_BITLEN_RSA = 131;      
      PEM_F_D2I_PKCS8PRIVATEKEY_BIO = 120;      
      PEM_F_D2I_PKCS8PRIVATEKEY_FP = 121;      
      PEM_F_DO_B2I = 132;      
      PEM_F_DO_B2I_BIO = 133;      
      PEM_F_DO_BLOB_HEADER = 134;      
      PEM_F_DO_PK8PKEY = 126;      
      PEM_F_DO_PK8PKEY_FP = 125;      
      PEM_F_DO_PVK_BODY = 135;      
      PEM_F_DO_PVK_HEADER = 136;      
      PEM_F_I2B_PVK = 137;      
      PEM_F_I2B_PVK_BIO = 138;      
      PEM_F_LOAD_IV = 101;      
      PEM_F_PEM_ASN1_READ = 102;      
      PEM_F_PEM_ASN1_READ_BIO = 103;      
      PEM_F_PEM_ASN1_WRITE = 104;      
      PEM_F_PEM_ASN1_WRITE_BIO = 105;      
      PEM_F_PEM_DEF_CALLBACK = 100;      
      PEM_F_PEM_DO_HEADER = 106;      
      PEM_F_PEM_GET_EVP_CIPHER_INFO = 107;      
      PEM_F_PEM_READ = 108;      
      PEM_F_PEM_READ_BIO = 109;      
      PEM_F_PEM_READ_BIO_DHPARAMS = 141;      
      PEM_F_PEM_READ_BIO_PARAMETERS = 140;      
      PEM_F_PEM_READ_BIO_PRIVATEKEY = 123;      
      PEM_F_PEM_READ_DHPARAMS = 142;      
      PEM_F_PEM_READ_PRIVATEKEY = 124;      
      PEM_F_PEM_SIGNFINAL = 112;      
      PEM_F_PEM_WRITE = 113;      
      PEM_F_PEM_WRITE_BIO = 114;      
      PEM_F_PEM_WRITE_PRIVATEKEY = 139;      
      PEM_F_PEM_X509_INFO_READ = 115;      
      PEM_F_PEM_X509_INFO_READ_BIO = 116;      
      PEM_F_PEM_X509_INFO_WRITE_BIO = 117;      
      PEM_R_BAD_BASE64_DECODE = 100;      
      PEM_R_BAD_DECRYPT = 101;      
      PEM_R_BAD_END_LINE = 102;      
      PEM_R_BAD_IV_CHARS = 103;      
      PEM_R_BAD_MAGIC_NUMBER = 116;      
      PEM_R_BAD_PASSWORD_READ = 104;      
      PEM_R_BAD_VERSION_NUMBER = 117;      
      PEM_R_BIO_WRITE_FAILURE = 118;      
      PEM_R_CIPHER_IS_NULL = 127;      
      PEM_R_ERROR_CONVERTING_PRIVATE_KEY = 115;      
      PEM_R_EXPECTING_PRIVATE_KEY_BLOB = 119;      
      PEM_R_EXPECTING_PUBLIC_KEY_BLOB = 120;      
      PEM_R_HEADER_TOO_LONG = 128;      
      PEM_R_INCONSISTENT_HEADER = 121;      
      PEM_R_KEYBLOB_HEADER_PARSE_ERROR = 122;      
      PEM_R_KEYBLOB_TOO_SHORT = 123;      
      PEM_R_MISSING_DEK_IV = 129;      
      PEM_R_NOT_DEK_INFO = 105;      
      PEM_R_NOT_ENCRYPTED = 106;      
      PEM_R_NOT_PROC_TYPE = 107;      
      PEM_R_NO_START_LINE = 108;      
      PEM_R_PROBLEMS_GETTING_PASSWORD = 109;      
      PEM_R_PVK_DATA_TOO_SHORT = 124;      
      PEM_R_PVK_TOO_SHORT = 125;      
      PEM_R_READ_KEY = 111;      
      PEM_R_SHORT_HEADER = 112;      
      PEM_R_UNEXPECTED_DEK_IV = 130;      
      PEM_R_UNSUPPORTED_CIPHER = 113;      
      PEM_R_UNSUPPORTED_ENCRYPTION = 114;      
      PEM_R_UNSUPPORTED_KEY_COMPONENTS = 126;      
{$define HEADER_HMAC_H}    
      HMAC_MAX_MD_CBLOCK = 128;      

function  HMAC_size(e:PHMAC_CTX):size_t;cdecl; external DLLUtilName;
function  HMAC_CTX_new:PHMAC_CTX;cdecl; external DLLUtilName;
function  HMAC_CTX_reset(ctx:PHMAC_CTX):cint;cdecl; external DLLUtilName;
procedure HMAC_CTX_free(ctx:PHMAC_CTX);cdecl; external DLLUtilName;
function  HMAC_Update(ctx:PHMAC_CTX; data:pbyte; len:size_t):cint;cdecl; external DLLUtilName;
function  HMAC_Final(ctx:PHMAC_CTX; md:pbyte; len:pcuint):cint;cdecl; external DLLUtilName;
function  HMAC(evp_md:PEVP_MD; key:pointer; key_len:cint; d:pbyte; n:size_t; 
               md:pbyte; md_len:pcuint):pbyte;cdecl; external DLLUtilName;
function  HMAC_CTX_copy(dctx:PHMAC_CTX; sctx:PHMAC_CTX):cint;cdecl; external DLLUtilName;
procedure HMAC_CTX_set_flags(ctx:PHMAC_CTX; flags:culong);cdecl; external DLLUtilName;
function  HMAC_CTX_get_md(ctx:PHMAC_CTX):PEVP_MD;cdecl; external DLLUtilName;
{$define HEADER_ASYNC_H}    
    const
      OSSL_BAD_ASYNC_FD = -(1);

      ASYNC_ERR = 0;      
      ASYNC_NO_JOBS = 1;      
      ASYNC_PAUSE = 2;      
      ASYNC_FINISH = 3;      

type
  TASYNC_cleanup_cb=procedure (para1:PASYNC_WAIT_CTX; para2:pointer; para3:cint; para4:pointer);cdecl;
  TASYNC_func_cb=function  (para1:pointer):cint;cdecl;

function  ASYNC_init_thread(max_size:size_t; init_size:size_t):cint;cdecl; external DLLUtilName;
procedure ASYNC_cleanup_thread;cdecl; external DLLUtilName;
function  ASYNC_WAIT_CTX_new:PASYNC_WAIT_CTX;cdecl; external DLLUtilName;
procedure ASYNC_WAIT_CTX_free(ctx:PASYNC_WAIT_CTX);cdecl; external DLLUtilName;
function  ASYNC_WAIT_CTX_set_wait_fd(ctx:PASYNC_WAIT_CTX; key:pointer; fd:cint; custom_data:pointer; cleanup:TASYNC_cleanup_cb):cint;cdecl; external DLLUtilName;
function  ASYNC_WAIT_CTX_get_fd(ctx:PASYNC_WAIT_CTX; key:pointer; fd:pcint; custom_data:Ppointer):cint;cdecl; external DLLUtilName;
function  ASYNC_WAIT_CTX_get_all_fds(ctx:PASYNC_WAIT_CTX; fd:pcint; numfds:Psize_t):cint;cdecl; external DLLUtilName;
function  ASYNC_WAIT_CTX_get_changed_fds(ctx:PASYNC_WAIT_CTX; addfd:pcint; numaddfds:Psize_t; delfd:pcint; numdelfds:Psize_t):cint;cdecl; external DLLUtilName;
function  ASYNC_WAIT_CTX_clear_fd(ctx:PASYNC_WAIT_CTX; key:pointer):cint;cdecl; external DLLUtilName;
function  ASYNC_is_capable:cint;cdecl; external DLLUtilName;
function  ASYNC_start_job(job:PPASYNC_JOB; ctx:PASYNC_WAIT_CTX; ret:pcint; func:TASYNC_func_cb; args:pointer;
               size:size_t):cint;cdecl; external DLLUtilName;
function  ASYNC_pause_job:cint;cdecl; external DLLUtilName;
function  ASYNC_get_current_job:PASYNC_JOB;cdecl; external DLLUtilName;
function  ASYNC_get_wait_ctx(job:PASYNC_JOB):PASYNC_WAIT_CTX;cdecl; external DLLUtilName;
procedure ASYNC_block_pause;cdecl; external DLLUtilName;
procedure ASYNC_unblock_pause;cdecl; external DLLUtilName;
function  ERR_load_ASYNC_strings:cint;cdecl; external DLLUtilName;
    const
      ASYNC_F_ASYNC_CTX_NEW = 100;      
      ASYNC_F_ASYNC_INIT_THREAD = 101;      
      ASYNC_F_ASYNC_JOB_NEW = 102;      
      ASYNC_F_ASYNC_PAUSE_JOB = 103;      
      ASYNC_F_ASYNC_START_FUNC = 104;      
      ASYNC_F_ASYNC_START_JOB = 105;      
      ASYNC_R_FAILED_TO_SET_POOL = 101;      
      ASYNC_R_FAILED_TO_SWAP_CONTEXT = 102;      
      ASYNC_R_INIT_FAILED = 105;      
      ASYNC_R_INVALID_POOL_SIZE = 103;      
{$define HEADER_CT_H}    
      SCT_MIN_RSA_BITS = 2048;      
      CT_V1_HASHLEN = SHA256_DIGEST_LENGTH;      
    type
      Pct_log_entry_type_t = ^Tct_log_entry_type_t;
      Tct_log_entry_type_t =  Longint;
      Const
        CT_LOG_ENTRY_TYPE_NOT_SET = -(1);
        CT_LOG_ENTRY_TYPE_X509 = 0;
        CT_LOG_ENTRY_TYPE_PRECERT = 1;

    type
      Psct_version_t = ^Tsct_version_t;
      Tsct_version_t =  Longint;
      Const
        SCT_VERSION_NOT_SET = -(1);
        SCT_VERSION_V1 = 0;

    type
      Psct_source_t = ^Tsct_source_t;
      Tsct_source_t =  Longint;
      Const
        SCT_SOURCE_UNKNOWN = 0;
        SCT_SOURCE_TLS_EXTENSION = 1;
        SCT_SOURCE_X509V3_EXTENSION = 2;
        SCT_SOURCE_OCSP_STAPLED_RESPONSE = 3;

    type
      Psct_validation_status_t = ^Tsct_validation_status_t;
      Tsct_validation_status_t =  Longint;
      Const
        SCT_VALIDATION_STATUS_NOT_SET = 0;
        SCT_VALIDATION_STATUS_UNKNOWN_LOG = 1;
        SCT_VALIDATION_STATUS_VALID = 2;
        SCT_VALIDATION_STATUS_INVALID = 3;
        SCT_VALIDATION_STATUS_UNVERIFIED = 4;
        SCT_VALIDATION_STATUS_UNKNOWN_VERSION = 5;

    type
      Pstack_st_SCT = ^Tstack_st_SCT;
      Tstack_st_SCT = record
          {undefined structure}
        end;
      PSCT=Pstack_st_SCT;
      PPSCT=^PSCT;

      PCTLOG=Pointer;
      PPCTLOG=^PCTLOG;

      PCT_POLICY_EVAL_CTX=Pointer;
      PCTLOG_STORE=Pointer;

      Tsk_SCT_compfunc = function  (a:PPSCT; b:PPSCT):cint;cdecl;

      Tsk_SCT_freefunc = procedure (a:PSCT);cdecl;

      Tsk_SCT_copyfunc = function  (a:PSCT):PSCT;cdecl;

      Tsk_CTLOG_compfunc = function  (a:PPCTLOG; b:PPCTLOG):cint;cdecl;

      Tsk_CTLOG_freefunc = procedure (a:PCTLOG);cdecl;

      Tsk_CTLOG_copyfunc = function  (a:PCTLOG):PCTLOG;cdecl;

procedure CT_POLICY_EVAL_CTX_free(ctx:PCT_POLICY_EVAL_CTX);cdecl; external DLLUtilName;
function  CT_POLICY_EVAL_CTX_get0_cert(ctx:PCT_POLICY_EVAL_CTX):PX509;cdecl; external DLLUtilName;
function  CT_POLICY_EVAL_CTX_set1_cert(ctx:PCT_POLICY_EVAL_CTX; cert:PX509):cint;cdecl; external DLLUtilName;
function  CT_POLICY_EVAL_CTX_get0_issuer(ctx:PCT_POLICY_EVAL_CTX):PX509;cdecl; external DLLUtilName;
function  CT_POLICY_EVAL_CTX_set1_issuer(ctx:PCT_POLICY_EVAL_CTX; issuer:PX509):cint;cdecl; external DLLUtilName;
function  CT_POLICY_EVAL_CTX_get0_log_store(ctx:PCT_POLICY_EVAL_CTX):PCTLOG_STORE;cdecl; external DLLUtilName;
procedure CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE(ctx:PCT_POLICY_EVAL_CTX; log_store:PCTLOG_STORE);cdecl; external DLLUtilName;
function  CT_POLICY_EVAL_CTX_get_time(ctx:PCT_POLICY_EVAL_CTX):uint64;cdecl; external DLLUtilName;
procedure CT_POLICY_EVAL_CTX_set_time(ctx:PCT_POLICY_EVAL_CTX; time_in_ms:uint64);cdecl; external DLLUtilName;
function  SCT_new:PSCT;cdecl; external DLLUtilName;
function  SCT_new_from_base64(version:byte; logid_base64:pbyte; entry_type:Tct_log_entry_type_t; timestamp:uint64; extensions_base64:pbyte; 
               signature_base64:pbyte):PSCT;cdecl; external DLLUtilName;
procedure SCT_free(sct:PSCT);cdecl; external DLLUtilName;
procedure SCT_LIST_free(a:Pstack_st_SCT);cdecl; external DLLUtilName;
function  SCT_get_version(sct:PSCT):Tsct_version_t;cdecl; external DLLUtilName;
function  SCT_set_version(sct:PSCT; version:Tsct_version_t):cint;cdecl; external DLLUtilName;
function  SCT_get_log_entry_type(sct:PSCT):Tct_log_entry_type_t;cdecl; external DLLUtilName;
function  SCT_set_log_entry_type(sct:PSCT; entry_type:Tct_log_entry_type_t):cint;cdecl; external DLLUtilName;
function  SCT_get0_log_id(sct:PSCT; log_id:Ppbyte):size_t;cdecl; external DLLUtilName;
function  SCT_set0_log_id(sct:PSCT; log_id:pbyte; log_id_len:size_t):cint;cdecl; external DLLUtilName;
function  SCT_set1_log_id(sct:PSCT; log_id:pbyte; log_id_len:size_t):cint;cdecl; external DLLUtilName;
function  SCT_get_timestamp(sct:PSCT):uint64;cdecl; external DLLUtilName;
procedure SCT_set_timestamp(sct:PSCT; timestamp:uint64);cdecl; external DLLUtilName;
function  SCT_get_signature_nid(sct:PSCT):cint;cdecl; external DLLUtilName;
function  SCT_set_signature_nid(sct:PSCT; nid:cint):cint;cdecl; external DLLUtilName;
function  SCT_get0_extensions(sct:PSCT; ext:Ppbyte):size_t;cdecl; external DLLUtilName;
procedure SCT_set0_extensions(sct:PSCT; ext:pbyte; ext_len:size_t);cdecl; external DLLUtilName;
function  SCT_set1_extensions(sct:PSCT; ext:pbyte; ext_len:size_t):cint;cdecl; external DLLUtilName;
function  SCT_get0_signature(sct:PSCT; sig:Ppbyte):size_t;cdecl; external DLLUtilName;
procedure SCT_set0_signature(sct:PSCT; sig:pbyte; sig_len:size_t);cdecl; external DLLUtilName;
function  SCT_set1_signature(sct:PSCT; sig:pbyte; sig_len:size_t):cint;cdecl; external DLLUtilName;
function  SCT_get_source(sct:PSCT):Tsct_source_t;cdecl; external DLLUtilName;
function  SCT_set_source(sct:PSCT; source:Tsct_source_t):cint;cdecl; external DLLUtilName;
function  SCT_validation_status_string(sct:PSCT):pbyte;cdecl; external DLLUtilName;
procedure SCT_print(sct:PSCT;_out:PBIO; indent:cint; logs:PCTLOG_STORE);cdecl; external DLLUtilName;
procedure SCT_LIST_print(sct_list:Pstack_st_SCT;_out:PBIO; indent:cint; separator:pbyte; logs:PCTLOG_STORE);cdecl; external DLLUtilName;
function  SCT_get_validation_status(sct:PSCT):Tsct_validation_status_t;cdecl; external DLLUtilName;
function  SCT_validate(sct:PSCT; ctx:PCT_POLICY_EVAL_CTX):cint;cdecl; external DLLUtilName;
function  SCT_LIST_validate(scts:Pstack_st_SCT; ctx:PCT_POLICY_EVAL_CTX):cint;cdecl; external DLLUtilName;
function  i2o_SCT_LIST(a:Pstack_st_SCT; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  i2d_SCT_LIST(a:Pstack_st_SCT; pp:Ppbyte):cint;cdecl; external DLLUtilName;
function  i2o_SCT(sct:PSCT;_out:Ppbyte):cint;cdecl; external DLLUtilName;
function  o2i_SCT(psct:PPSCT;_in:Ppbyte; len:size_t):PSCT;cdecl; external DLLUtilName;
function  CTLOG_new(public_key:PEVP_PKEY; name:pbyte):PCTLOG;cdecl; external DLLUtilName;
function  CTLOG_new_from_base64(ct_log:PPCTLOG; pkey_base64:pbyte; name:pbyte):cint;cdecl; external DLLUtilName;
procedure CTLOG_free(log:PCTLOG);cdecl; external DLLUtilName;
function  CTLOG_get0_name(log:PCTLOG):pbyte;cdecl; external DLLUtilName;
procedure CTLOG_get0_log_id(log:PCTLOG; log_id:PPuint8; log_id_len:Psize_t);cdecl; external DLLUtilName;
function  CTLOG_get0_public_key(log:PCTLOG):PEVP_PKEY;cdecl; external DLLUtilName;
function  CTLOG_STORE_new:PCTLOG_STORE;cdecl; external DLLUtilName;
procedure CTLOG_STORE_free(store:PCTLOG_STORE);cdecl; external DLLUtilName;
function  CTLOG_STORE_get0_log_by_id(store:PCTLOG_STORE; log_id:Puint8; log_id_len:size_t):PCTLOG;cdecl; external DLLUtilName;
function  CTLOG_STORE_load_file(store:PCTLOG_STORE; _file:pbyte):cint;cdecl; external DLLUtilName;
function  CTLOG_STORE_load_default_file(store:PCTLOG_STORE):cint;cdecl; external DLLUtilName;
function  ERR_load_CT_strings:cint;cdecl; external DLLUtilName;

    type
      Ptls_session_ticket_ext= ^Ttls_session_ticket_ext_st;
      Ttls_session_ticket_ext_st = record
          length : cushort;
          data : pointer;
        end;

      Pssl_crock= ^Tssl_crock_st;
      Tssl_crock_st = Pssl;

      Pstack_st_SSL_CIPHER = ^Tstack_st_SSL_CIPHER;
      Tstack_st_SSL_CIPHER = record
          {undefined structure}
        end;

      Pstack_st_SSL_COMP = ^Tstack_st_SSL_COMP;
      Tstack_st_SSL_COMP = record
          {undefined structure}
        end;
      PSSL_COMP=Pstack_st_SSL_COMP;
      PPSSL_COMP=^PSSL_COMP;

      Psrtp_protection_profile= ^Tsrtp_protection_profile_st;
      Tsrtp_protection_profile_st = record
          name : pbyte;
          id : culong;
        end;
      PPSRTP_PROTECTION_PROFILE=^PSRTP_PROTECTION_PROFILE;

      Pstack_st_SRTP_PROTECTION_PROFILE = ^Tstack_st_SRTP_PROTECTION_PROFILE;
      Tstack_st_SRTP_PROTECTION_PROFILE = record
          {undefined structure}
        end;

      Tsk_SRTP_PROTECTION_PROFILE_compfunc = function  (a:PPSRTP_PROTECTION_PROFILE; b:PPSRTP_PROTECTION_PROFILE):cint;cdecl;

      Tsk_SRTP_PROTECTION_PROFILE_freefunc = procedure (a:PSRTP_PROTECTION_PROFILE);cdecl;

      Tsk_SRTP_PROTECTION_PROFILE_copyfunc = function  (a:PSRTP_PROTECTION_PROFILE):PSRTP_PROTECTION_PROFILE;cdecl;

      Ttls_session_ticket_ext_cb_fn = function  (s:PSSL; data:Ppbyte; len:size_t; arg:pointer):cint;cdecl;

      Ttls_session_secret_cb_fn = function  (s:PSSL; secret:pointer; secret_len:pcint; peer_ciphers:Pstack_st_SSL_CIPHER; cipher:PPSSL_CIPHER; 
                   arg:pointer):cint;cdecl;

      Tcustom_ext_add_cb = function  (s:PSSL; ext_type:cuint;_out:Ppbyte; outlen:Psize_t; al:pcint; 
                   add_arg:pointer):cint;cdecl;

      Tcustom_ext_free_cb = procedure (s:PSSL; ext_type:cuint;_out:pbyte; add_arg:pointer);cdecl;

      Tcustom_ext_parse_cb = function  (s:PSSL; ext_type:cuint;_in:pbyte; inlen:size_t; al:pcint; 
                   parse_arg:pointer):cint;cdecl;

      TSSL_verify_cb = function  (preverify_ok:cint; x509_ctx:PX509_STORE_CTX):cint;cdecl;

    const
      SSL_OP_LEGACY_SERVER_CONNECT = $00000004;      
      SSL_OP_TLSEXT_PADDING = $00000010;      
      SSL_OP_SAFARI_ECDHE_ECDSA_BUG = $00000040;      
      SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = $00000800;      
      SSL_OP_NO_QUERY_MTU = $00001000;      
      SSL_OP_COOKIE_EXCHANGE = $00002000;      
      SSL_OP_NO_TICKET = $00004000;      
      SSL_OP_CISCO_ANYCONNECT = $00008000;      
      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = $00010000;      
      SSL_OP_NO_COMPRESSION = $00020000;      
      SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = $00040000;      
      SSL_OP_NO_ENCRYPT_THEN_MAC = $00080000;      
      SSL_OP_CIPHER_SERVER_PREFERENCE = $00400000;      
      SSL_OP_TLS_ROLLBACK_BUG = $00800000;      
      SSL_OP_NO_SSLv3 = $02000000;      
      SSL_OP_NO_TLSv1 = $04000000;      
      SSL_OP_NO_TLSv1_2 = $08000000;      
      SSL_OP_NO_TLSv1_1 = $10000000;      
      SSL_OP_NO_DTLSv1 = $04000000;      
      SSL_OP_NO_DTLSv1_2 = $08000000;      
      SSL_OP_NO_SSL_MASK = ((SSL_OP_NO_SSLv3 or SSL_OP_NO_TLSv1) or SSL_OP_NO_TLSv1_1) or SSL_OP_NO_TLSv1_2;      
      SSL_OP_NO_DTLS_MASK = SSL_OP_NO_DTLSv1 or SSL_OP_NO_DTLSv1_2;      
      SSL_OP_CRYPTOPRO_TLSEXT_BUG = $80000000;      
      SSL_OP_ALL = (((SSL_OP_CRYPTOPRO_TLSEXT_BUG or SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) or SSL_OP_LEGACY_SERVER_CONNECT) or SSL_OP_TLSEXT_PADDING) or SSL_OP_SAFARI_ECDHE_ECDSA_BUG;      
      SSL_OP_MICROSOFT_SESS_ID_BUG = $0;      
      SSL_OP_NETSCAPE_CHALLENGE_BUG = $0;      
      SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = $0;      
      SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = $0;      
      SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = $0;      
      SSL_OP_MSIE_SSLV2_RSA_PADDING = $0;      
      SSL_OP_SSLEAY_080_CLIENT_DH_BUG = $0;      
      SSL_OP_TLS_D5_BUG = $0;      
      SSL_OP_TLS_BLOCK_PADDING_BUG = $0;      
      SSL_OP_SINGLE_ECDH_USE = $0;      
      SSL_OP_SINGLE_DH_USE = $0;      
      SSL_OP_EPHEMERAL_RSA = $0;      
      SSL_OP_NO_SSLv2 = $0;      
      SSL_OP_PKCS1_CHECK_1 = $0;      
      SSL_OP_PKCS1_CHECK_2 = $0;      
      SSL_OP_NETSCAPE_CA_DN_BUG = $0;      
      SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = $0;      
      SSL_MODE_ENABLE_PARTIAL_WRITE = $00000001;      
      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = $00000002;      
      SSL_MODE_AUTO_RETRY = $00000004;      
      SSL_MODE_NO_AUTO_CHAIN = $00000008;      
      SSL_MODE_RELEASE_BUFFERS = $00000010;      
      SSL_MODE_SEND_CLIENTHELLO_TIME = $00000020;      
      SSL_MODE_SEND_SERVERHELLO_TIME = $00000040;      
      SSL_MODE_SEND_FALLBACK_SCSV = $00000080;      
      SSL_MODE_ASYNC = $00000100;      
      SSL_CERT_FLAG_TLS_STRICT = $00000001;      
      SSL_CERT_FLAG_SUITEB_128_LOS_ONLY = $10000;      
      SSL_CERT_FLAG_SUITEB_192_LOS = $20000;      
      SSL_CERT_FLAG_SUITEB_128_LOS = $30000;      
      SSL_CERT_FLAG_BROKEN_PROTOCOL = $10000000;      
      SSL_BUILD_CHAIN_FLAG_UNTRUSTED = $1;      
      SSL_BUILD_CHAIN_FLAG_NO_ROOT = $2;      
      SSL_BUILD_CHAIN_FLAG_CHECK = $4;      
      SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR = $8;      
      SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR = $10;      
      CERT_PKEY_VALID = $1;      
      CERT_PKEY_SIGN = $2;      
      CERT_PKEY_EE_SIGNATURE = $10;      
      CERT_PKEY_CA_SIGNATURE = $20;      
      CERT_PKEY_EE_PARAM = $40;      
      CERT_PKEY_CA_PARAM = $80;      
      CERT_PKEY_EXPLICIT_SIGN = $100;      
      CERT_PKEY_ISSUER_NAME = $200;      
      CERT_PKEY_CERT_TYPE = $400;      
      CERT_PKEY_SUITEB = $800;      
      SSL_CONF_FLAG_CMDLINE = $1;      
      SSL_CONF_FLAG_FILE = $2;      
      SSL_CONF_FLAG_CLIENT = $4;      
      SSL_CONF_FLAG_SERVER = $8;      
      SSL_CONF_FLAG_SHOW_ERRORS = $10;      
      SSL_CONF_FLAG_CERTIFICATE = $20;      
      SSL_CONF_FLAG_REQUIRE_PRIVATE = $40;      
      SSL_CONF_TYPE_UNKNOWN = $0;      
      SSL_CONF_TYPE_STRING = $1;      
      SSL_CONF_TYPE_FILE = $2;      
      SSL_CONF_TYPE_DIR = $3;      
      SSL_CONF_TYPE_NONE = $4;      

function  SSL_CTX_get_options(ctx:PSSL_CTX):culong;cdecl; external DLLSSLName;
function  SSL_get_options(s:PSSL):culong;cdecl; external DLLSSLName;
function  SSL_CTX_clear_options(ctx:PSSL_CTX; op:culong):culong;cdecl; external DLLSSLName;
function  SSL_clear_options(s:PSSL; op:culong):culong;cdecl; external DLLSSLName;
function  SSL_CTX_set_options(ctx:PSSL_CTX; op:culong):culong;cdecl; external DLLSSLName;
function  SSL_set_options(s:PSSL; op:culong):culong;cdecl; external DLLSSLName;

    function  SSL_CTX_set_mode(ctx:PSSL_CTX;op : clong) : clong;

    function  SSL_CTX_clear_mode(ctx:PSSL_CTX;op : clong) : clong;

    function  SSL_CTX_get_mode(ctx : PSSL_CTX) : clong;

    function  SSL_clear_mode(ssl:PSSL;op : clong) : clong;

    function  SSL_set_mode(ssl:PSSL;op : clong) : clong;

    function  SSL_get_mode(ssl : PSSL) : clong;

    function  SSL_set_mtu(ssl : PSSL;mtu : clong) : clong;

    function  DTLS_set_link_mtu(ssl : PSSL;mtu : clong) : clong;

    function  DTLS_get_link_min_mtu(ssl : PSSL) : clong;

    function  SSL_get_secure_renegotiation_support(ssl : PSSL) : clong;

    function  SSL_heartbeat(ssl : PSSL) : clong;

    function  SSL_CTX_set_cert_flags(ctx:PSSL_CTX;op : clong) : clong;

    function  SSL_set_cert_flags(s:PSSL;op : clong) : clong;

    function  SSL_CTX_clear_cert_flags(ctx:PSSL_CTX;op : clong) : clong;

    function  SSL_clear_cert_flags(s:PSSL;op : clong) : clong;

procedure SSL_CTX_set_msg_callback(ctx:PSSL_CTX; cb:Tssl_msg_callback_cb);cdecl; external DLLSSLName;
procedure SSL_set_msg_callback(ssl:PSSL; cb:Tssl_msg_callback_cb);cdecl; external DLLSSLName;

    function  SSL_CTX_set_msg_callback_arg(ctx:PSSL_CTX;arg : Pointer) : clong;

    function  SSL_set_msg_callback_arg(ssl:PSSL;arg : Pointer) : clong;

    function  SSL_get_extms_support(s : PSSL) : clong;

function  SSL_SRP_CTX_init(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_CTX_SRP_CTX_init(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_SRP_CTX_free(ctx:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_CTX_SRP_CTX_free(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_srp_server_param_with_username(s:PSSL; ad:pcint):cint;cdecl; external DLLSSLName;
function  SRP_Calc_A_param(s:PSSL):cint;cdecl; external DLLSSLName;

    const
      SSL_SESSION_CACHE_MAX_SIZE_DEFAULT = 1024*20;

    type
      TGEN_SESSION_CB = function  (ssl:PSSL; id:pbyte; id_len:pcuint):cint;cdecl;

    const
      SSL_SESS_CACHE_OFF = $0000;      
      SSL_SESS_CACHE_CLIENT = $0001;      
      SSL_SESS_CACHE_SERVER = $0002;      
      SSL_SESS_CACHE_BOTH = SSL_SESS_CACHE_CLIENT or SSL_SESS_CACHE_SERVER;      
      SSL_SESS_CACHE_NO_AUTO_CLEAR = $0080;      
      SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = $0100;      
      SSL_SESS_CACHE_NO_INTERNAL_STORE = $0200;      
      SSL_SESS_CACHE_NO_INTERNAL = SSL_SESS_CACHE_NO_INTERNAL_LOOKUP or SSL_SESS_CACHE_NO_INTERNAL_STORE;      

    function  SSL_CTX_sess_number(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_connect(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_connect_good(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_connect_renegotiate(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_accept(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_accept_renegotiate(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_accept_good(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_hits(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_cb_hits(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_misses(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_timeouts(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_sess_cache_full(ctx : PSSL_CTX) : clong;

procedure SSL_CTX_sess_set_new_cb(ctx:PSSL_CTX; new_session_cb:Tssl_ctx_new_session_cb);cdecl; external DLLSSLName;
function  SSL_CTX_sess_get_new_cb(ctx:PSSL_CTX):Tssl_ctx_new_session_cb;cdecl; external DLLSSLName;
procedure SSL_CTX_sess_set_remove_cb(ctx:PSSL_CTX; remove_session_cb:Tssl_ctx_remove_session_cb);cdecl; external DLLSSLName;
function  SSL_CTX_sess_get_remove_cb(ctx:PSSL_CTX):Tssl_ctx_remove_session_cb;cdecl; external DLLSSLName;
procedure SSL_CTX_sess_set_get_cb(ctx:PSSL_CTX; get_session_cb:Tssl_ctx_get_session_cb);cdecl; external DLLSSLName;
function  SSL_CTX_sess_get_get_cb(ctx:PSSL_CTX):Tssl_ctx_get_session_cb;cdecl; external DLLSSLName;
procedure SSL_CTX_set_info_callback(ctx:PSSL_CTX; cb:Tssl_ctx_info_cb);cdecl; external DLLSSLName;
function  SSL_CTX_get_info_callback(ctx:PSSL_CTX):Tssl_ctx_info_cb;cdecl; external DLLSSLName;
procedure SSL_CTX_set_client_cert_cb(ctx:PSSL_CTX; client_cert_cb:Tssl_ctx_client_cert_cb);cdecl; external DLLSSLName;
function  SSL_CTX_get_client_cert_cb(ctx:PSSL_CTX):Tssl_ctx_client_cert_cb;cdecl; external DLLSSLName;
function  SSL_CTX_set_client_cert_engine(ctx:PSSL_CTX; e:PENGINE):cint;cdecl; external DLLSSLName;
procedure SSL_CTX_set_cookie_generate_cb(ctx:PSSL_CTX; app_gen_cookie_cb:Tssl_ctx_gen_cookie_cb);cdecl; external DLLSSLName;
procedure SSL_CTX_set_cookie_verify_cb(ctx:PSSL_CTX; app_verify_cookie_cb:Tssl_ctx_verify_cookie_cb);cdecl; external DLLSSLName;

procedure SSL_CTX_set_next_protos_advertised_cb(s:PSSL_CTX; cb:Tnext_proto_advertised_cb; arg:pointer);cdecl;
procedure SSL_CTX_set_next_proto_select_cb(s:PSSL_CTX; cb:Tnext_proto_select_cb; arg:pointer);cdecl;
procedure SSL_get0_next_proto_negotiated(s:PSSL; data:Ppbyte; len:pcunsigned);cdecl;
function  SSL_select_next_proto(_out:Ppbyte; outlen:pbyte;_in:pbyte; inlen:cuint; client:pbyte; client_len:cuint):cint;cdecl;

    const
      OPENSSL_NPN_UNSUPPORTED = 0;      
      OPENSSL_NPN_NEGOTIATED = 1;      
      OPENSSL_NPN_NO_OVERLAP = 2;      

function  SSL_CTX_set_alpn_protos(ctx:PSSL_CTX; protos:pbyte; protos_len:cuint):cint;cdecl;
function  SSL_set_alpn_protos(ssl:PSSL; protos:pbyte; protos_len:cuint):cint;cdecl;
procedure SSL_CTX_set_alpn_select_cb(ctx:PSSL_CTX; cb:Tnext_proto_select_cb; arg:pointer);cdecl;
procedure SSL_get0_alpn_selected(ssl:PSSL; data:Ppbyte; len:pcuint);cdecl;

    const
      PSK_MAX_IDENTITY_LEN = 128;      
      PSK_MAX_PSK_LEN = 256;      

type
 TSSL_CTX_psk_client_cb=function  (ssl:PSSL; hint:pbyte; identity:pbyte; max_identity_len:cuint; psk:pbyte; max_psk_len:cuint):cuint;cdecl;
 TSSL_CTX_psk_server_cb=function  (ssl:PSSL; identity:pbyte; psk:pbyte; max_psk_len:cuint):cuint;cdecl;

procedure SSL_CTX_set_psk_client_callback(ctx:PSSL_CTX; psk_client_callback:TSSL_CTX_psk_client_cb);cdecl; external DLLSSLName;
procedure SSL_set_psk_client_callback(ssl:PSSL; psk_client_callback:TSSL_CTX_psk_client_cb);cdecl; external DLLSSLName;
procedure SSL_CTX_set_psk_server_callback(ctx:PSSL_CTX; psk_server_callback:TSSL_CTX_psk_server_cb);cdecl; external DLLSSLName;
procedure SSL_set_psk_server_callback(ssl:PSSL; psk_server_callback:TSSL_CTX_psk_server_cb);cdecl; external DLLSSLName;
function  SSL_CTX_use_psk_identity_hint(ctx:PSSL_CTX; identity_hint:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_use_psk_identity_hint(s:PSSL; identity_hint:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_get_psk_identity_hint(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_get_psk_identity(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_CTX_has_client_custom_ext(ctx:PSSL_CTX; ext_type:cuint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_add_client_custom_ext(ctx:PSSL_CTX; ext_type:cuint; add_cb:Tcustom_ext_add_cb; free_cb:Tcustom_ext_free_cb; add_arg:pointer; 
               parse_cb:Tcustom_ext_parse_cb; parse_arg:pointer):cint;cdecl; external DLLSSLName;
function  SSL_CTX_add_server_custom_ext(ctx:PSSL_CTX; ext_type:cuint; add_cb:Tcustom_ext_add_cb; free_cb:Tcustom_ext_free_cb; add_arg:pointer; 
               parse_cb:Tcustom_ext_parse_cb; parse_arg:pointer):cint;cdecl; external DLLSSLName;
function  SSL_extension_supported(ext_type:cuint):cint;cdecl; external DLLSSLName;

    const
      SSL_NOTHING = 1;      
      SSL_WRITING = 2;      
      SSL_READING = 3;      
      SSL_X509_LOOKUP = 4;      
      SSL_ASYNC_PAUSED = 5;      
      SSL_ASYNC_NO_JOBS = 6;      

    function  SSL_want_nothing(s : PSSL) : Boolean;

    function  SSL_want_read(s : PSSL) : Boolean;

    function  SSL_want_write(s : PSSL) : Boolean;

    function  SSL_want_x509_lookup(s : PSSL) : Boolean;

    function  SSL_want_async(s : PSSL) : Boolean;

    function  SSL_want_async_job(s : PSSL) : Boolean;

    const
      SSL_MAC_FLAG_READ_MAC_STREAM = 1;      
      SSL_MAC_FLAG_WRITE_MAC_STREAM = 2;      
{$define HEADER_SSL2_H}    
      SSL2_VERSION = $0002;      
      SSL2_MT_CLIENT_HELLO = 1;      
{$define HEADER_SSL3_H}    
      SSL3_CK_SCSV = $030000FF;      
      SSL3_CK_FALLBACK_SCSV = $03005600;      
      SSL3_CK_RSA_NULL_MD5 = $03000001;      
      SSL3_CK_RSA_NULL_SHA = $03000002;      
      SSL3_CK_RSA_RC4_40_MD5 = $03000003;      
      SSL3_CK_RSA_RC4_128_MD5 = $03000004;      
      SSL3_CK_RSA_RC4_128_SHA = $03000005;      
      SSL3_CK_RSA_RC2_40_MD5 = $03000006;      
      SSL3_CK_RSA_IDEA_128_SHA = $03000007;      
      SSL3_CK_RSA_DES_40_CBC_SHA = $03000008;      
      SSL3_CK_RSA_DES_64_CBC_SHA = $03000009;      
      SSL3_CK_RSA_DES_192_CBC3_SHA = $0300000A;      
      SSL3_CK_DH_DSS_DES_40_CBC_SHA = $0300000B;      
      SSL3_CK_DH_DSS_DES_64_CBC_SHA = $0300000C;      
      SSL3_CK_DH_DSS_DES_192_CBC3_SHA = $0300000D;      
      SSL3_CK_DH_RSA_DES_40_CBC_SHA = $0300000E;      
      SSL3_CK_DH_RSA_DES_64_CBC_SHA = $0300000F;      
      SSL3_CK_DH_RSA_DES_192_CBC3_SHA = $03000010;      
      SSL3_CK_DHE_DSS_DES_40_CBC_SHA = $03000011;      
      SSL3_CK_EDH_DSS_DES_40_CBC_SHA = SSL3_CK_DHE_DSS_DES_40_CBC_SHA;      
      SSL3_CK_DHE_DSS_DES_64_CBC_SHA = $03000012;      
      SSL3_CK_EDH_DSS_DES_64_CBC_SHA = SSL3_CK_DHE_DSS_DES_64_CBC_SHA;      
      SSL3_CK_DHE_DSS_DES_192_CBC3_SHA = $03000013;      
      SSL3_CK_EDH_DSS_DES_192_CBC3_SHA = SSL3_CK_DHE_DSS_DES_192_CBC3_SHA;      
      SSL3_CK_DHE_RSA_DES_40_CBC_SHA = $03000014;      
      SSL3_CK_EDH_RSA_DES_40_CBC_SHA = SSL3_CK_DHE_RSA_DES_40_CBC_SHA;      
      SSL3_CK_DHE_RSA_DES_64_CBC_SHA = $03000015;      
      SSL3_CK_EDH_RSA_DES_64_CBC_SHA = SSL3_CK_DHE_RSA_DES_64_CBC_SHA;      
      SSL3_CK_DHE_RSA_DES_192_CBC3_SHA = $03000016;      
      SSL3_CK_EDH_RSA_DES_192_CBC3_SHA = SSL3_CK_DHE_RSA_DES_192_CBC3_SHA;      
      SSL3_CK_ADH_RC4_40_MD5 = $03000017;      
      SSL3_CK_ADH_RC4_128_MD5 = $03000018;      
      SSL3_CK_ADH_DES_40_CBC_SHA = $03000019;      
      SSL3_CK_ADH_DES_64_CBC_SHA = $0300001A;      
      SSL3_CK_ADH_DES_192_CBC_SHA = $0300001B;      

      SSL3_SSL_SESSION_ID_LENGTH = 32;      
      SSL3_MAX_SSL_SESSION_ID_LENGTH = 32;      
      SSL3_MASTER_SECRET_SIZE = 48;      
      SSL3_RANDOM_SIZE = 32;      
      SSL3_SESSION_ID_SIZE = 32;      
      SSL3_RT_HEADER_LENGTH = 5;      
      SSL3_HM_HEADER_LENGTH = 4;      
      SSL3_ALIGN_PAYLOAD = 8;      
      SSL3_RT_MAX_MD_SIZE = 64;      
      SSL_RT_MAX_CIPHER_BLOCK_SIZE = 16;      
      SSL3_RT_MAX_EXTRA = 16384;      
      SSL3_RT_MAX_PLAIN_LENGTH = 16384;      
      SSL3_RT_MAX_COMPRESSED_OVERHEAD = 1024;      
      SSL3_RT_MAX_ENCRYPTED_OVERHEAD = 256+SSL3_RT_MAX_MD_SIZE;      
      SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD = SSL_RT_MAX_CIPHER_BLOCK_SIZE+SSL3_RT_MAX_MD_SIZE;      
      SSL3_RT_MAX_COMPRESSED_LENGTH = SSL3_RT_MAX_PLAIN_LENGTH+SSL3_RT_MAX_COMPRESSED_OVERHEAD;      
      SSL3_RT_MAX_ENCRYPTED_LENGTH = SSL3_RT_MAX_ENCRYPTED_OVERHEAD+SSL3_RT_MAX_COMPRESSED_LENGTH;      
      SSL3_RT_MAX_PACKET_SIZE = SSL3_RT_MAX_ENCRYPTED_LENGTH+SSL3_RT_HEADER_LENGTH;      
      SSL3_MD_CLIENT_FINISHED_CONST = '\x43\x4C\x4E\x54';      
      SSL3_MD_SERVER_FINISHED_CONST = '\x53\x52\x56\x52';      
      SSL3_VERSION = $0300;      
      SSL3_VERSION_MAJOR = $03;      
      SSL3_VERSION_MINOR = $00;      
      SSL3_RT_CHANGE_CIPHER_SPEC = 20;      
      SSL3_RT_ALERT = 21;      
      SSL3_RT_HANDSHAKE = 22;      
      SSL3_RT_APPLICATION_DATA = 23;      
      DTLS1_RT_HEARTBEAT = 24;      
      TLS1_RT_CRYPTO = $1000;      
      TLS1_RT_CRYPTO_PREMASTER = TLS1_RT_CRYPTO or $1;      
      TLS1_RT_CRYPTO_CLIENT_RANDOM = TLS1_RT_CRYPTO or $2;      
      TLS1_RT_CRYPTO_SERVER_RANDOM = TLS1_RT_CRYPTO or $3;      
      TLS1_RT_CRYPTO_MASTER = TLS1_RT_CRYPTO or $4;      
      TLS1_RT_CRYPTO_READ = $0000;      
      TLS1_RT_CRYPTO_WRITE = $0100;      
      TLS1_RT_CRYPTO_MAC = TLS1_RT_CRYPTO or $5;      
      TLS1_RT_CRYPTO_KEY = TLS1_RT_CRYPTO or $6;      
      TLS1_RT_CRYPTO_IV = TLS1_RT_CRYPTO or $7;      
      TLS1_RT_CRYPTO_FIXED_IV = TLS1_RT_CRYPTO or $8;      
      SSL3_RT_HEADER = $100;      
      SSL3_AL_WARNING = 1;      
      SSL3_AL_FATAL = 2;      
      SSL3_AD_CLOSE_NOTIFY = 0;      
      SSL3_AD_UNEXPECTED_MESSAGE = 10;      
      SSL3_AD_BAD_RECORD_MAC = 20;      
      SSL3_AD_DECOMPRESSION_FAILURE = 30;      
      SSL3_AD_HANDSHAKE_FAILURE = 40;      
      SSL3_AD_NO_CERTIFICATE = 41;      
      SSL3_AD_BAD_CERTIFICATE = 42;      
      SSL3_AD_UNSUPPORTED_CERTIFICATE = 43;      
      SSL3_AD_CERTIFICATE_REVOKED = 44;      
      SSL3_AD_CERTIFICATE_EXPIRED = 45;      
      SSL3_AD_CERTIFICATE_UNKNOWN = 46;      
      SSL3_AD_ILLEGAL_PARAMETER = 47;      
      TLS1_HB_REQUEST = 1;      
      TLS1_HB_RESPONSE = 2;      
      SSL3_CT_RSA_SIGN = 1;      
      SSL3_CT_DSS_SIGN = 2;      
      SSL3_CT_RSA_FIXED_DH = 3;      
      SSL3_CT_DSS_FIXED_DH = 4;      
      SSL3_CT_RSA_EPHEMERAL_DH = 5;      
      SSL3_CT_DSS_EPHEMERAL_DH = 6;      
      SSL3_CT_FORTEZZA_DMS = 20;      
      SSL3_CT_NUMBER = 9;      
      SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS = $0001;      
      TLS1_FLAGS_TLS_PADDING_BUG = $0;      
      TLS1_FLAGS_SKIP_CERT_VERIFY = $0010;      
      TLS1_FLAGS_ENCRYPT_THEN_MAC_READ = $0100;      
      TLS1_FLAGS_ENCRYPT_THEN_MAC = TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;      
      TLS1_FLAGS_RECEIVED_EXTMS = $0200;      
      TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE = $0400;      
      SSL3_MT_HELLO_REQUEST = 0;      
      SSL3_MT_CLIENT_HELLO = 1;      
      SSL3_MT_SERVER_HELLO = 2;      
      SSL3_MT_NEWSESSION_TICKET = 4;      
      SSL3_MT_CERTIFICATE = 11;      
      SSL3_MT_SERVER_KEY_EXCHANGE = 12;      
      SSL3_MT_CERTIFICATE_REQUEST = 13;      
      SSL3_MT_SERVER_DONE = 14;      
      SSL3_MT_CERTIFICATE_VERIFY = 15;      
      SSL3_MT_CLIENT_KEY_EXCHANGE = 16;      
      SSL3_MT_FINISHED = 20;      
      SSL3_MT_CERTIFICATE_STATUS = 22;      
      SSL3_MT_NEXT_PROTO = 67;      
      DTLS1_MT_HELLO_VERIFY_REQUEST = 3;      
      SSL3_MT_CHANGE_CIPHER_SPEC = $0101;      
      SSL3_MT_CCS = 1;      
      SSL3_CC_READ = $01;      
      SSL3_CC_WRITE = $02;      
      SSL3_CC_CLIENT = $10;      
      SSL3_CC_SERVER = $20;      
      SSL3_CHANGE_CIPHER_CLIENT_WRITE = SSL3_CC_CLIENT or SSL3_CC_WRITE;      
      SSL3_CHANGE_CIPHER_SERVER_READ = SSL3_CC_SERVER or SSL3_CC_READ;      
      SSL3_CHANGE_CIPHER_CLIENT_READ = SSL3_CC_CLIENT or SSL3_CC_READ;      
      SSL3_CHANGE_CIPHER_SERVER_WRITE = SSL3_CC_SERVER or SSL3_CC_WRITE;      
{$define HEADER_TLS1_H}    
      OPENSSL_TLS_SECURITY_LEVEL = 1;      
      TLS1_VERSION = $0301;      
      TLS1_1_VERSION = $0302;      
      TLS1_2_VERSION = $0303;      
      TLS_MAX_VERSION = TLS1_2_VERSION;      
      TLS_ANY_VERSION = $10000;      
      TLS1_VERSION_MAJOR = $03;      
      TLS1_VERSION_MINOR = $01;      
      TLS1_1_VERSION_MAJOR = $03;      
      TLS1_1_VERSION_MINOR = $02;      
      TLS1_2_VERSION_MAJOR = $03;      
      TLS1_2_VERSION_MINOR = $03;      

    function  TLS1_get_version(s : PSSL) : cint;

    function  TLS1_get_client_version(s : PSSL) : cint;

    const
      TLS1_AD_DECRYPTION_FAILED = 21;      
      TLS1_AD_RECORD_OVERFLOW = 22;      
      TLS1_AD_UNKNOWN_CA = 48;      
      TLS1_AD_ACCESS_DENIED = 49;      
      TLS1_AD_DECODE_ERROR = 50;      
      TLS1_AD_DECRYPT_ERROR = 51;      
      TLS1_AD_EXPORT_RESTRICTION = 60;      
      TLS1_AD_PROTOCOL_VERSION = 70;      
      TLS1_AD_INSUFFICIENT_SECURITY = 71;      
      TLS1_AD_INTERNAL_ERROR = 80;      
      TLS1_AD_INAPPROPRIATE_FALLBACK = 86;      
      TLS1_AD_USER_CANCELLED = 90;      
      TLS1_AD_NO_RENEGOTIATION = 100;      
      TLS1_AD_UNSUPPORTED_EXTENSION = 110;      
      TLS1_AD_CERTIFICATE_UNOBTAINABLE = 111;      
      TLS1_AD_UNRECOGNIZED_NAME = 112;      
      TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE = 113;      
      TLS1_AD_BAD_CERTIFICATE_HASH_VALUE = 114;      
      TLS1_AD_UNKNOWN_PSK_IDENTITY = 115;      
      TLS1_AD_NO_APPLICATION_PROTOCOL = 120;      
      TLSEXT_TYPE_server_name = 0;      
      TLSEXT_TYPE_max_fragment_length = 1;      
      TLSEXT_TYPE_client_certificate_url = 2;      
      TLSEXT_TYPE_trusted_ca_keys = 3;      
      TLSEXT_TYPE_truncated_hmac = 4;      
      TLSEXT_TYPE_status_request = 5;      
      TLSEXT_TYPE_user_mapping = 6;      
      TLSEXT_TYPE_client_authz = 7;      
      TLSEXT_TYPE_server_authz = 8;      
      TLSEXT_TYPE_cert_type = 9;      
      TLSEXT_TYPE_elliptic_curves = 10;      
      TLSEXT_TYPE_ec_point_formats = 11;      
      TLSEXT_TYPE_srp = 12;      
      TLSEXT_TYPE_signature_algorithms = 13;      
      TLSEXT_TYPE_use_srtp = 14;      
      TLSEXT_TYPE_heartbeat = 15;      
      TLSEXT_TYPE_application_layer_protocol_negotiation = 16;      
      TLSEXT_TYPE_signed_certificate_timestamp = 18;      
      TLSEXT_TYPE_padding = 21;      
      TLSEXT_TYPE_encrypt_then_mac = 22;      
      TLSEXT_TYPE_extended_master_secret = 23;      
      TLSEXT_TYPE_session_ticket = 35;      
      TLSEXT_TYPE_renegotiate = $ff01;      
      TLSEXT_TYPE_next_proto_neg = 13172;      
      TLSEXT_NAMETYPE_host_name = 0;      
      TLSEXT_STATUSTYPE_ocsp = 1;      
      TLSEXT_ECPOINTFORMAT_first = 0;      
      TLSEXT_ECPOINTFORMAT_uncompressed = 0;      
      TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime = 1;      
      TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 = 2;      
      TLSEXT_ECPOINTFORMAT_last = 2;      
      TLSEXT_signature_anonymous = 0;      
      TLSEXT_signature_rsa = 1;      
      TLSEXT_signature_dsa = 2;      
      TLSEXT_signature_ecdsa = 3;      
      TLSEXT_signature_gostr34102001 = 237;      
      TLSEXT_signature_gostr34102012_256 = 238;      
      TLSEXT_signature_gostr34102012_512 = 239;      
      TLSEXT_signature_num = 7;      
      TLSEXT_hash_none = 0;      
      TLSEXT_hash_md5 = 1;      
      TLSEXT_hash_sha1 = 2;      
      TLSEXT_hash_sha224 = 3;      
      TLSEXT_hash_sha256 = 4;      
      TLSEXT_hash_sha384 = 5;      
      TLSEXT_hash_sha512 = 6;      
      TLSEXT_hash_gostr3411 = 237;      
      TLSEXT_hash_gostr34112012_256 = 238;      
      TLSEXT_hash_gostr34112012_512 = 239;      
      TLSEXT_hash_num = 10;      
      TLSEXT_nid_unknown = $1000000;      
      TLSEXT_curve_P_256 = 23;      
      TLSEXT_curve_P_384 = 24;      
      TLSEXT_MAXLEN_host_name = 255;      

function  SSL_get_servername(s:PSSL; _type:cint):pbyte;cdecl; external DLLUtilName;
function  SSL_get_servername_type(s:PSSL):cint;cdecl; external DLLUtilName;
function  SSL_export_keying_material(s:PSSL;_out:pbyte; olen:size_t; _label:pbyte; llen:size_t; 
               context:pbyte; contextlen:size_t; use_context:cint):cint;cdecl; external DLLUtilName;
function  SSL_get_sigalgs(s:PSSL; idx:cint; psign:pcint; phash:pcint; psignandhash:pcint; 
               rsig:pbyte; rhash:pbyte):cint;cdecl; external DLLUtilName;
function  SSL_get_shared_sigalgs(s:PSSL; idx:cint; psign:pcint; phash:pcint; psignandhash:pcint; 
               rsig:pbyte; rhash:pbyte):cint;cdecl; external DLLUtilName;
function  SSL_check_chain(s:PSSL; x:PX509; pk:PEVP_PKEY; chain:Pstack_st_X509):cint;cdecl; external DLLUtilName;

    function  SSL_set_tlsext_host_name(s : PSSL;name : Pointer) : clong;

    function  SSL_set_tlsext_debug_arg(ssl : PSSL;arg : Pointer) : clong;

    function  SSL_get_tlsext_status_type(ssl : PSSL) : clong;

    function  SSL_set_tlsext_status_type(ssl : PSSL;_type : clong) : clong;

    function  SSL_get_tlsext_status_exts(ssl : PSSL;arg : Pointer) : clong;

    function  SSL_set_tlsext_status_exts(ssl : PSSL;arg : Pointer) : clong;

    function  SSL_get_tlsext_status_ids(ssl : PSSL;arg : Pointer) : clong;

    function  SSL_set_tlsext_status_ids(ssl : PSSL;arg : Pointer) : clong;

    function  SSL_get_tlsext_status_ocsp_resp(ssl : PSSL;arg : Pointer) : clong;

    function  SSL_set_tlsext_status_ocsp_resp(ssl : PSSL;arg:Pointer;arglen : clong) : clong;

    const
      SSL_TLSEXT_ERR_OK = 0;      
      SSL_TLSEXT_ERR_ALERT_WARNING = 1;      
      SSL_TLSEXT_ERR_ALERT_FATAL = 2;      
      SSL_TLSEXT_ERR_NOACK = 3;      

    function  SSL_CTX_set_tlsext_servername_arg(ctx:PSSL_CTX;arg : Pointer) : clong;

    function  SSL_CTX_get_tlsext_ticket_keys(ctx:PSSL_CTX;keys:Pointer;keylen : clong) : clong;

    function  SSL_CTX_set_tlsext_ticket_keys(ctx:PSSL_CTX;keys:Pointer;keylen : clong) : clong;

    function  SSL_CTX_get_tlsext_status_arg(ssl:PSSL_CTX;arg : Pointer) : clong;

    function  SSL_CTX_set_tlsext_status_arg(ssl:PSSL_CTX;arg : Pointer) : clong;

    function  SSL_CTX_set_tlsext_status_type(ssl:PSSL_CTX;_type : clong) : clong;

    function  SSL_CTX_get_tlsext_status_type(ssl : PSSL_CTX) : clong;

    const
      SSL_DTLSEXT_HB_ENABLED = $01;      
      SSL_DTLSEXT_HB_DONT_SEND_REQUESTS = $02;      
      SSL_DTLSEXT_HB_DONT_RECV_REQUESTS = $04;      

    function  SSL_get_dtlsext_heartbeat_pending(ssl : PSSL) : clong;

    function  SSL_set_dtlsext_heartbeat_no_requests(ssl:PSSL;arg : clong) : clong;

    function  SSL_get_tlsext_heartbeat_pending(ssl : PSSL) : clong;

    function  SSL_set_tlsext_heartbeat_no_requests(ssl:PSSL;arg : clong) : clong;

    const
      TLS1_CK_PSK_WITH_RC4_128_SHA = $0300008A;      
      TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA = $0300008B;      
      TLS1_CK_PSK_WITH_AES_128_CBC_SHA = $0300008C;      
      TLS1_CK_PSK_WITH_AES_256_CBC_SHA = $0300008D;      
      TLS1_CK_DHE_PSK_WITH_RC4_128_SHA = $0300008E;      
      TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA = $0300008F;      
      TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA = $03000090;      
      TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA = $03000091;      
      TLS1_CK_RSA_PSK_WITH_RC4_128_SHA = $03000092;      
      TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA = $03000093;      
      TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA = $03000094;      
      TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA = $03000095;      
      TLS1_CK_PSK_WITH_AES_128_GCM_SHA256 = $030000A8;      
      TLS1_CK_PSK_WITH_AES_256_GCM_SHA384 = $030000A9;      
      TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256 = $030000AA;      
      TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384 = $030000AB;      
      TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256 = $030000AC;      
      TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384 = $030000AD;      
      TLS1_CK_PSK_WITH_AES_128_CBC_SHA256 = $030000AE;      
      TLS1_CK_PSK_WITH_AES_256_CBC_SHA384 = $030000AF;      
      TLS1_CK_PSK_WITH_NULL_SHA256 = $030000B0;      
      TLS1_CK_PSK_WITH_NULL_SHA384 = $030000B1;      
      TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256 = $030000B2;      
      TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384 = $030000B3;      
      TLS1_CK_DHE_PSK_WITH_NULL_SHA256 = $030000B4;      
      TLS1_CK_DHE_PSK_WITH_NULL_SHA384 = $030000B5;      
      TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256 = $030000B6;      
      TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384 = $030000B7;      
      TLS1_CK_RSA_PSK_WITH_NULL_SHA256 = $030000B8;      
      TLS1_CK_RSA_PSK_WITH_NULL_SHA384 = $030000B9;      
      TLS1_CK_PSK_WITH_NULL_SHA = $0300002C;      
      TLS1_CK_DHE_PSK_WITH_NULL_SHA = $0300002D;      
      TLS1_CK_RSA_PSK_WITH_NULL_SHA = $0300002E;      
      TLS1_CK_RSA_WITH_AES_128_SHA = $0300002F;      
      TLS1_CK_DH_DSS_WITH_AES_128_SHA = $03000030;      
      TLS1_CK_DH_RSA_WITH_AES_128_SHA = $03000031;      
      TLS1_CK_DHE_DSS_WITH_AES_128_SHA = $03000032;      
      TLS1_CK_DHE_RSA_WITH_AES_128_SHA = $03000033;      
      TLS1_CK_ADH_WITH_AES_128_SHA = $03000034;      
      TLS1_CK_RSA_WITH_AES_256_SHA = $03000035;      
      TLS1_CK_DH_DSS_WITH_AES_256_SHA = $03000036;      
      TLS1_CK_DH_RSA_WITH_AES_256_SHA = $03000037;      
      TLS1_CK_DHE_DSS_WITH_AES_256_SHA = $03000038;      
      TLS1_CK_DHE_RSA_WITH_AES_256_SHA = $03000039;      
      TLS1_CK_ADH_WITH_AES_256_SHA = $0300003A;      
      TLS1_CK_RSA_WITH_NULL_SHA256 = $0300003B;      
      TLS1_CK_RSA_WITH_AES_128_SHA256 = $0300003C;      
      TLS1_CK_RSA_WITH_AES_256_SHA256 = $0300003D;      
      TLS1_CK_DH_DSS_WITH_AES_128_SHA256 = $0300003E;      
      TLS1_CK_DH_RSA_WITH_AES_128_SHA256 = $0300003F;      
      TLS1_CK_DHE_DSS_WITH_AES_128_SHA256 = $03000040;      
      TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA = $03000041;      
      TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = $03000042;      
      TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = $03000043;      
      TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = $03000044;      
      TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = $03000045;      
      TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA = $03000046;      
      TLS1_CK_DHE_RSA_WITH_AES_128_SHA256 = $03000067;      
      TLS1_CK_DH_DSS_WITH_AES_256_SHA256 = $03000068;      
      TLS1_CK_DH_RSA_WITH_AES_256_SHA256 = $03000069;      
      TLS1_CK_DHE_DSS_WITH_AES_256_SHA256 = $0300006A;      
      TLS1_CK_DHE_RSA_WITH_AES_256_SHA256 = $0300006B;      
      TLS1_CK_ADH_WITH_AES_128_SHA256 = $0300006C;      
      TLS1_CK_ADH_WITH_AES_256_SHA256 = $0300006D;      
      TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA = $03000084;      
      TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = $03000085;      
      TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = $03000086;      
      TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = $03000087;      
      TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = $03000088;      
      TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA = $03000089;      
      TLS1_CK_RSA_WITH_SEED_SHA = $03000096;      
      TLS1_CK_DH_DSS_WITH_SEED_SHA = $03000097;      
      TLS1_CK_DH_RSA_WITH_SEED_SHA = $03000098;      
      TLS1_CK_DHE_DSS_WITH_SEED_SHA = $03000099;      
      TLS1_CK_DHE_RSA_WITH_SEED_SHA = $0300009A;      
      TLS1_CK_ADH_WITH_SEED_SHA = $0300009B;      
      TLS1_CK_RSA_WITH_AES_128_GCM_SHA256 = $0300009C;      
      TLS1_CK_RSA_WITH_AES_256_GCM_SHA384 = $0300009D;      
      TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256 = $0300009E;      
      TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384 = $0300009F;      
      TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256 = $030000A0;      
      TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384 = $030000A1;      
      TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256 = $030000A2;      
      TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384 = $030000A3;      
      TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256 = $030000A4;      
      TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384 = $030000A5;      
      TLS1_CK_ADH_WITH_AES_128_GCM_SHA256 = $030000A6;      
      TLS1_CK_ADH_WITH_AES_256_GCM_SHA384 = $030000A7;      
      TLS1_CK_RSA_WITH_AES_128_CCM = $0300C09C;      
      TLS1_CK_RSA_WITH_AES_256_CCM = $0300C09D;      
      TLS1_CK_DHE_RSA_WITH_AES_128_CCM = $0300C09E;      
      TLS1_CK_DHE_RSA_WITH_AES_256_CCM = $0300C09F;      
      TLS1_CK_RSA_WITH_AES_128_CCM_8 = $0300C0A0;      
      TLS1_CK_RSA_WITH_AES_256_CCM_8 = $0300C0A1;      
      TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8 = $0300C0A2;      
      TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8 = $0300C0A3;      
      TLS1_CK_PSK_WITH_AES_128_CCM = $0300C0A4;      
      TLS1_CK_PSK_WITH_AES_256_CCM = $0300C0A5;      
      TLS1_CK_DHE_PSK_WITH_AES_128_CCM = $0300C0A6;      
      TLS1_CK_DHE_PSK_WITH_AES_256_CCM = $0300C0A7;      
      TLS1_CK_PSK_WITH_AES_128_CCM_8 = $0300C0A8;      
      TLS1_CK_PSK_WITH_AES_256_CCM_8 = $0300C0A9;      
      TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8 = $0300C0AA;      
      TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8 = $0300C0AB;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM = $0300C0AC;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM = $0300C0AD;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8 = $0300C0AE;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8 = $0300C0AF;      
      TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256 = $030000BA;      
      TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = $030000BB;      
      TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = $030000BC;      
      TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = $030000BD;      
      TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = $030000BE;      
      TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256 = $030000BF;      
      TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256 = $030000C0;      
      TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = $030000C1;      
      TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = $030000C2;      
      TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = $030000C3;      
      TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = $030000C4;      
      TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256 = $030000C5;      
      TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA = $0300C001;      
      TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA = $0300C002;      
      TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = $0300C003;      
      TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA = $0300C004;      
      TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA = $0300C005;      
      TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA = $0300C006;      
      TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA = $0300C007;      
      TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = $0300C008;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = $0300C009;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = $0300C00A;      
      TLS1_CK_ECDH_RSA_WITH_NULL_SHA = $0300C00B;      
      TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA = $0300C00C;      
      TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA = $0300C00D;      
      TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA = $0300C00E;      
      TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA = $0300C00F;      
      TLS1_CK_ECDHE_RSA_WITH_NULL_SHA = $0300C010;      
      TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA = $0300C011;      
      TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA = $0300C012;      
      TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA = $0300C013;      
      TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA = $0300C014;      
      TLS1_CK_ECDH_anon_WITH_NULL_SHA = $0300C015;      
      TLS1_CK_ECDH_anon_WITH_RC4_128_SHA = $0300C016;      
      TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA = $0300C017;      
      TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA = $0300C018;      
      TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA = $0300C019;      
      TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA = $0300C01A;      
      TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = $0300C01B;      
      TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = $0300C01C;      
      TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA = $0300C01D;      
      TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = $0300C01E;      
      TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = $0300C01F;      
      TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA = $0300C020;      
      TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = $0300C021;      
      TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = $0300C022;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256 = $0300C023;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384 = $0300C024;      
      TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256 = $0300C025;      
      TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384 = $0300C026;      
      TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256 = $0300C027;      
      TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384 = $0300C028;      
      TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256 = $0300C029;      
      TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384 = $0300C02A;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = $0300C02B;      
      TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = $0300C02C;      
      TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = $0300C02D;      
      TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = $0300C02E;      
      TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = $0300C02F;      
      TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = $0300C030;      
      TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256 = $0300C031;      
      TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384 = $0300C032;      
      TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA = $0300C033;      
      TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = $0300C034;      
      TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA = $0300C035;      
      TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA = $0300C036;      
      TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = $0300C037;      
      TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = $0300C038;      
      TLS1_CK_ECDHE_PSK_WITH_NULL_SHA = $0300C039;      
      TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256 = $0300C03A;      
      TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384 = $0300C03B;      
      TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = $0300C072;      
      TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = $0300C073;      
      TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = $0300C074;      
      TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = $0300C075;      
      TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = $0300C076;      
      TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = $0300C077;      
      TLS1_CK_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = $0300C078;      
      TLS1_CK_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = $0300C079;      
      TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256 = $0300C094;      
      TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384 = $0300C095;      
      TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = $0300C096;      
      TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = $0300C097;      
      TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = $0300C098;      
      TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = $0300C099;      
      TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = $0300C09A;      
      TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = $0300C09B;      
      TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305 = $0300CCA8;      
      TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = $0300CCA9;      
      TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305 = $0300CCAA;      
      TLS1_CK_PSK_WITH_CHACHA20_POLY1305 = $0300CCAB;      
      TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305 = $0300CCAC;      
      TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305 = $0300CCAD;      
      TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305 = $0300CCAE;

      TLS_CT_RSA_SIGN = 1;      
      TLS_CT_DSS_SIGN = 2;      
      TLS_CT_RSA_FIXED_DH = 3;      
      TLS_CT_DSS_FIXED_DH = 4;      
      TLS_CT_ECDSA_SIGN = 64;      
      TLS_CT_RSA_FIXED_ECDH = 65;      
      TLS_CT_ECDSA_FIXED_ECDH = 66;      
      TLS_CT_GOST01_SIGN = 22;      
      TLS_CT_GOST12_SIGN = 238;      
      TLS_CT_GOST12_512_SIGN = 239;      
      TLS_CT_NUMBER = 9;      
      TLS1_FINISH_MAC_LENGTH = 12;      
      TLS_MD_MAX_CONST_SIZE = 22;      
      TLS_MD_CLIENT_FINISH_CONST_SIZE = 15;      
      TLS_MD_SERVER_FINISH_CONST_SIZE = 15;      
      TLS_MD_KEY_EXPANSION_CONST_SIZE = 13;      
      TLS_MD_CLIENT_WRITE_KEY_CONST_SIZE = 16;      
      TLS_MD_SERVER_WRITE_KEY_CONST_SIZE = 16;      
      TLS_MD_IV_BLOCK_CONST_SIZE = 8;      
      TLS_MD_MASTER_SECRET_CONST_SIZE = 13;      
      TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE = 22;      


{$define HEADER_DTLS1_H}    

    const
      DTLS1_VERSION = $FEFF;      
      DTLS1_2_VERSION = $FEFD;      
      DTLS_MIN_VERSION = DTLS1_VERSION;      
      DTLS_MAX_VERSION = DTLS1_2_VERSION;      
      DTLS1_VERSION_MAJOR = $FE;      
      DTLS1_BAD_VER = $0100;      
      DTLS_ANY_VERSION = $1FFFF;      
      DTLS1_COOKIE_LENGTH = 256;      
      DTLS1_RT_HEADER_LENGTH = 13;      
      DTLS1_HM_HEADER_LENGTH = 12;      
      DTLS1_HM_BAD_FRAGMENT = -(2);      
      DTLS1_HM_FRAGMENT_RETRY = -(3);      
      DTLS1_CCS_HEADER_LENGTH = 1;      
      DTLS1_AL_HEADER_LENGTH = 2;      
      DTLS1_TMO_READ_COUNT = 2;      
      DTLS1_TMO_WRITE_COUNT = 2;      
      DTLS1_TMO_ALERT_COUNT = 12;      
{$define HEADER_D1_SRTP_H}    
      SRTP_AES128_CM_SHA1_80 = $0001;      
      SRTP_AES128_CM_SHA1_32 = $0002;      
      SRTP_AES128_F8_SHA1_80 = $0003;      
      SRTP_AES128_F8_SHA1_32 = $0004;      
      SRTP_NULL_SHA1_80 = $0005;      
      SRTP_NULL_SHA1_32 = $0006;      
      SRTP_AEAD_AES_128_GCM = $0007;      
      SRTP_AEAD_AES_256_GCM = $0008;      

function  SSL_CTX_set_tlsext_use_srtp(ctx:PSSL_CTX; profiles:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_set_tlsext_use_srtp(ssl:PSSL; profiles:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_get_selected_srtp_profile(s:PSSL):PSRTP_PROTECTION_PROFILE;cdecl; external DLLSSLName;

    type
      Tsk_SSL_CIPHER_compfunc = function  (a:PPSSL_CIPHER; b:PPSSL_CIPHER):cint;cdecl;

      Tsk_SSL_CIPHER_freefunc = procedure (a:PSSL_CIPHER);cdecl;

      Tsk_SSL_CIPHER_copyfunc = function  (a:PSSL_CIPHER):PSSL_CIPHER;cdecl;

      Tsk_SSL_COMP_compfunc = function  (a:PPSSL_COMP; b:PPSSL_COMP):cint;cdecl;

      Tsk_SSL_COMP_freefunc = procedure (a:PSSL_COMP);cdecl;

      Tsk_SSL_COMP_copyfunc = function  (a:PSSL_COMP):PSSL_COMP;cdecl;

    function  SSL_get_app_data(s : PSSL) : Pointer;

    function  SSL_SESSION_set_app_data(s : PSSL_SESSION;a : Pointer) : cint;

    function  SSL_SESSION_get_app_data(s : PSSL_SESSION) : Pointer;

    function  SSL_CTX_get_app_data(ctx : PSSL_CTX) : Pointer;

    function  SSL_CTX_set_app_data(ctx : PSSL_CTX;arg : Pointer) : cint;

    const
      SSL_ST_CONNECT = $1000;      
      SSL_ST_ACCEPT = $2000;      
      SSL_ST_MASK = $0FFF;      
      SSL_CB_LOOP = $01;      
      SSL_CB_EXIT = $02;      
      SSL_CB_READ = $04;      
      SSL_CB_WRITE = $08;      
      SSL_CB_ALERT = $4000;      
      SSL_CB_READ_ALERT = SSL_CB_ALERT or SSL_CB_READ;      
      SSL_CB_WRITE_ALERT = SSL_CB_ALERT or SSL_CB_WRITE;      
      SSL_CB_ACCEPT_LOOP = SSL_ST_ACCEPT or SSL_CB_LOOP;      
      SSL_CB_ACCEPT_EXIT = SSL_ST_ACCEPT or SSL_CB_EXIT;      
      SSL_CB_CONNECT_LOOP = SSL_ST_CONNECT or SSL_CB_LOOP;      
      SSL_CB_CONNECT_EXIT = SSL_ST_CONNECT or SSL_CB_EXIT;      
      SSL_CB_HANDSHAKE_START = $10;      
      SSL_CB_HANDSHAKE_DONE = $20;      

    function  SSL_in_connect_init(a : PSSL) : Boolean;

    function  SSL_in_accept_init(a : PSSL) : Boolean;

function  SSL_in_init(s:PSSL):cint;cdecl; external DLLUtilName;
function  SSL_in_before(s:PSSL):cint;cdecl; external DLLUtilName;
function  SSL_is_init_finished(s:PSSL):cint;cdecl; external DLLUtilName;

    const
      SSL_ST_READ_HEADER = $F0;      
      SSL_ST_READ_BODY = $F1;      
      SSL_ST_READ_DONE = $F2;      

function  SSL_get_finished(s:PSSL; buf:pointer; count:size_t):size_t;cdecl; external DLLUtilName;
function  SSL_get_peer_finished(s:PSSL; buf:pointer; count:size_t):size_t;cdecl; external DLLUtilName;

    const
      SSL_VERIFY_NONE = $00;      
      SSL_VERIFY_PEER = $01;      
      SSL_VERIFY_FAIL_IF_NO_PEER_CERT = $02;      
      SSL_VERIFY_CLIENT_ONCE = $04;      

    function  OpenSSL_add_ssl_algorithms : longint;

    function  SSLeay_add_ssl_algorithms : longint;

    function  SSL_get_cipher(s : PSSL) : PByte;

    function  SSL_get_cipher_bits(s : PSSL;np : pcint) : cint;

    function  SSL_get_cipher_version(s : PSSL) : PByte;

    function  SSL_get_cipher_name(s : PSSL) : PByte;

    function  SSL_get_time(a : PSSL_SESSION) : clong;

    function  SSL_set_time(a : PSSL_SESSION;b : clong) : clong;

    function  SSL_get_timeout(a : PSSL_SESSION) : clong;

    function  SSL_set_timeout(a : PSSL_SESSION;b : clong) : clong;

    function  d2i_SSL_SESSION_bio(bp:PBIO;s_id : Ppointer) : Pointer;

    function  i2d_SSL_SESSION_bio(bp:PBIO;s_id : PByte) : cint;

function  PEM_read_bio_SSL_SESSION(bp:PBIO; x:PPSSL_SESSION; cb:Ppem_password_cb; u:pointer):PSSL_SESSION;cdecl; external DLLSSLName;
//function  PEM_read_SSL_SESSION(fp:PFILE; x:PPSSL_SESSION; cb:Ppem_password_cb; u:pointer):PSSL_SESSION;cdecl; external DLLSSLName;
function  PEM_write_bio_SSL_SESSION(bp:PBIO; x:PSSL_SESSION):cint;cdecl; external DLLSSLName;
//function  PEM_write_SSL_SESSION(fp:PFILE; x:PSSL_SESSION):cint;cdecl; external DLLSSLName;

    const
      SSL_AD_REASON_OFFSET = 1000;      
      SSL_AD_CLOSE_NOTIFY = SSL3_AD_CLOSE_NOTIFY;      
      SSL_AD_UNEXPECTED_MESSAGE = SSL3_AD_UNEXPECTED_MESSAGE;      
      SSL_AD_BAD_RECORD_MAC = SSL3_AD_BAD_RECORD_MAC;      
      SSL_AD_DECRYPTION_FAILED = TLS1_AD_DECRYPTION_FAILED;      
      SSL_AD_RECORD_OVERFLOW = TLS1_AD_RECORD_OVERFLOW;      
      SSL_AD_DECOMPRESSION_FAILURE = SSL3_AD_DECOMPRESSION_FAILURE;      
      SSL_AD_HANDSHAKE_FAILURE = SSL3_AD_HANDSHAKE_FAILURE;      
      SSL_AD_NO_CERTIFICATE = SSL3_AD_NO_CERTIFICATE;      
      SSL_AD_BAD_CERTIFICATE = SSL3_AD_BAD_CERTIFICATE;      
      SSL_AD_UNSUPPORTED_CERTIFICATE = SSL3_AD_UNSUPPORTED_CERTIFICATE;      
      SSL_AD_CERTIFICATE_REVOKED = SSL3_AD_CERTIFICATE_REVOKED;      
      SSL_AD_CERTIFICATE_EXPIRED = SSL3_AD_CERTIFICATE_EXPIRED;      
      SSL_AD_CERTIFICATE_UNKNOWN = SSL3_AD_CERTIFICATE_UNKNOWN;      
      SSL_AD_ILLEGAL_PARAMETER = SSL3_AD_ILLEGAL_PARAMETER;      
      SSL_AD_UNKNOWN_CA = TLS1_AD_UNKNOWN_CA;      
      SSL_AD_ACCESS_DENIED = TLS1_AD_ACCESS_DENIED;      
      SSL_AD_DECODE_ERROR = TLS1_AD_DECODE_ERROR;      
      SSL_AD_DECRYPT_ERROR = TLS1_AD_DECRYPT_ERROR;      
      SSL_AD_EXPORT_RESTRICTION = TLS1_AD_EXPORT_RESTRICTION;      
      SSL_AD_PROTOCOL_VERSION = TLS1_AD_PROTOCOL_VERSION;      
      SSL_AD_INSUFFICIENT_SECURITY = TLS1_AD_INSUFFICIENT_SECURITY;      
      SSL_AD_INTERNAL_ERROR = TLS1_AD_INTERNAL_ERROR;      
      SSL_AD_USER_CANCELLED = TLS1_AD_USER_CANCELLED;      
      SSL_AD_NO_RENEGOTIATION = TLS1_AD_NO_RENEGOTIATION;      
      SSL_AD_UNSUPPORTED_EXTENSION = TLS1_AD_UNSUPPORTED_EXTENSION;      
      SSL_AD_CERTIFICATE_UNOBTAINABLE = TLS1_AD_CERTIFICATE_UNOBTAINABLE;      
      SSL_AD_UNRECOGNIZED_NAME = TLS1_AD_UNRECOGNIZED_NAME;      
      SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE = TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE;      
      SSL_AD_BAD_CERTIFICATE_HASH_VALUE = TLS1_AD_BAD_CERTIFICATE_HASH_VALUE;      
      SSL_AD_UNKNOWN_PSK_IDENTITY = TLS1_AD_UNKNOWN_PSK_IDENTITY;      
      SSL_AD_INAPPROPRIATE_FALLBACK = TLS1_AD_INAPPROPRIATE_FALLBACK;      
      SSL_AD_NO_APPLICATION_PROTOCOL = TLS1_AD_NO_APPLICATION_PROTOCOL;      
      SSL_ERROR_NONE = 0;      
      SSL_ERROR_SSL = 1;      
      SSL_ERROR_WANT_READ = 2;      
      SSL_ERROR_WANT_WRITE = 3;      
      SSL_ERROR_WANT_X509_LOOKUP = 4;      
      SSL_ERROR_SYSCALL = 5;      
      SSL_ERROR_ZERO_RETURN = 6;      
      SSL_ERROR_WANT_CONNECT = 7;      
      SSL_ERROR_WANT_ACCEPT = 8;      
      SSL_ERROR_WANT_ASYNC = 9;      
      SSL_ERROR_WANT_ASYNC_JOB = 10;      
      SSL_CTRL_SET_TMP_DH = 3;      
      SSL_CTRL_SET_TMP_ECDH = 4;      
      SSL_CTRL_SET_TMP_DH_CB = 6;      
      SSL_CTRL_GET_CLIENT_CERT_REQUEST = 9;      
      SSL_CTRL_GET_NUM_RENEGOTIATIONS = 10;      
      SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS = 11;      
      SSL_CTRL_GET_TOTAL_RENEGOTIATIONS = 12;      
      SSL_CTRL_GET_FLAGS = 13;      
      SSL_CTRL_EXTRA_CHAIN_CERT = 14;      
      SSL_CTRL_SET_MSG_CALLBACK = 15;      
      SSL_CTRL_SET_MSG_CALLBACK_ARG = 16;      
      SSL_CTRL_SET_MTU = 17;      
      SSL_CTRL_SESS_NUMBER = 20;      
      SSL_CTRL_SESS_CONNECT = 21;      
      SSL_CTRL_SESS_CONNECT_GOOD = 22;      
      SSL_CTRL_SESS_CONNECT_RENEGOTIATE = 23;      
      SSL_CTRL_SESS_ACCEPT = 24;      
      SSL_CTRL_SESS_ACCEPT_GOOD = 25;      
      SSL_CTRL_SESS_ACCEPT_RENEGOTIATE = 26;      
      SSL_CTRL_SESS_HIT = 27;      
      SSL_CTRL_SESS_CB_HIT = 28;      
      SSL_CTRL_SESS_MISSES = 29;      
      SSL_CTRL_SESS_TIMEOUTS = 30;      
      SSL_CTRL_SESS_CACHE_FULL = 31;      
      SSL_CTRL_MODE = 33;      
      SSL_CTRL_GET_READ_AHEAD = 40;      
      SSL_CTRL_SET_READ_AHEAD = 41;      
      SSL_CTRL_SET_SESS_CACHE_SIZE = 42;      
      SSL_CTRL_GET_SESS_CACHE_SIZE = 43;      
      SSL_CTRL_SET_SESS_CACHE_MODE = 44;      
      SSL_CTRL_GET_SESS_CACHE_MODE = 45;      
      SSL_CTRL_GET_MAX_CERT_LIST = 50;      
      SSL_CTRL_SET_MAX_CERT_LIST = 51;      
      SSL_CTRL_SET_MAX_SEND_FRAGMENT = 52;      
      SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53;      
      SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54;      
      SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;      
      SSL_CTRL_SET_TLSEXT_DEBUG_CB = 56;      
      SSL_CTRL_SET_TLSEXT_DEBUG_ARG = 57;      
      SSL_CTRL_GET_TLSEXT_TICKET_KEYS = 58;      
      SSL_CTRL_SET_TLSEXT_TICKET_KEYS = 59;      
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = 63;      
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = 64;      
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE = 65;      
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS = 66;      
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS = 67;      
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS = 68;      
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS = 69;      
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70;      
      SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = 71;      
      SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB = 72;      
      SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB = 75;      
      SSL_CTRL_SET_SRP_VERIFY_PARAM_CB = 76;      
      SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB = 77;      
      SSL_CTRL_SET_SRP_ARG = 78;      
      SSL_CTRL_SET_TLS_EXT_SRP_USERNAME = 79;      
      SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH = 80;      
      SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD = 81;      
      SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT = 85;      
      SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING = 86;      
      SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS = 87;      
      DTLS_CTRL_GET_TIMEOUT = 73;      
      DTLS_CTRL_HANDLE_TIMEOUT = 74;      
      SSL_CTRL_GET_RI_SUPPORT = 76;      
      SSL_CTRL_CLEAR_MODE = 78;      
      SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB = 79;      
      SSL_CTRL_GET_EXTRA_CHAIN_CERTS = 82;      
      SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS = 83;      
      SSL_CTRL_CHAIN = 88;      
      SSL_CTRL_CHAIN_CERT = 89;      
      SSL_CTRL_GET_CURVES = 90;      
      SSL_CTRL_SET_CURVES = 91;      
      SSL_CTRL_SET_CURVES_LIST = 92;      
      SSL_CTRL_GET_SHARED_CURVE = 93;      
      SSL_CTRL_SET_SIGALGS = 97;      
      SSL_CTRL_SET_SIGALGS_LIST = 98;      
      SSL_CTRL_CERT_FLAGS = 99;      
      SSL_CTRL_CLEAR_CERT_FLAGS = 100;      
      SSL_CTRL_SET_CLIENT_SIGALGS = 101;      
      SSL_CTRL_SET_CLIENT_SIGALGS_LIST = 102;      
      SSL_CTRL_GET_CLIENT_CERT_TYPES = 103;      
      SSL_CTRL_SET_CLIENT_CERT_TYPES = 104;      
      SSL_CTRL_BUILD_CERT_CHAIN = 105;      
      SSL_CTRL_SET_VERIFY_CERT_STORE = 106;      
      SSL_CTRL_SET_CHAIN_CERT_STORE = 107;      
      SSL_CTRL_GET_PEER_SIGNATURE_NID = 108;      
      SSL_CTRL_GET_SERVER_TMP_KEY = 109;      
      SSL_CTRL_GET_RAW_CIPHERLIST = 110;      
      SSL_CTRL_GET_EC_POINT_FORMATS = 111;      
      SSL_CTRL_GET_CHAIN_CERTS = 115;      
      SSL_CTRL_SELECT_CURRENT_CERT = 116;      
      SSL_CTRL_SET_CURRENT_CERT = 117;      
      SSL_CTRL_SET_DH_AUTO = 118;      
      DTLS_CTRL_SET_LINK_MTU = 120;      
      DTLS_CTRL_GET_LINK_MIN_MTU = 121;      
      SSL_CTRL_GET_EXTMS_SUPPORT = 122;      
      SSL_CTRL_SET_MIN_PROTO_VERSION = 123;      
      SSL_CTRL_SET_MAX_PROTO_VERSION = 124;      
      SSL_CTRL_SET_SPLIT_SEND_FRAGMENT = 125;      
      SSL_CTRL_SET_MAX_PIPELINES = 126;      
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE = 127;      
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB = 128;      
      SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129;      
      SSL_CTRL_GET_MIN_PROTO_VERSION = 130;      
      SSL_CTRL_GET_MAX_PROTO_VERSION = 131;      
      SSL_CERT_SET_FIRST = 1;      
      SSL_CERT_SET_NEXT = 2;      
      SSL_CERT_SET_SERVER = 3;      

      SSL_CTRL_TLS_EXT_SEND_HEARTBEAT = SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT;
      SSL_CTRL_GET_TLS_EXT_HEARTBEAT_PENDING = SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING;
      SSL_CTRL_SET_TLS_EXT_HEARTBEAT_NO_REQUESTS = SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS;
      SSL_TLSEXT_HB_ENABLED = SSL_DTLSEXT_HB_ENABLED;
      SSL_TLSEXT_HB_DONT_SEND_REQUESTS = SSL_DTLSEXT_HB_DONT_SEND_REQUESTS;
      SSL_TLSEXT_HB_DONT_RECV_REQUESTS = SSL_DTLSEXT_HB_DONT_RECV_REQUESTS;

    function  DTLSv1_get_timeout(ssl:PSSL;arg : Pointer) : clong;

    function  DTLSv1_handle_timeout(ssl : PSSL) : clong;

    function  SSL_num_renegotiations(ssl : PSSL) : clong;

    function  SSL_clear_num_renegotiations(ssl : PSSL) : clong;

    function  SSL_total_renegotiations(ssl : PSSL) : clong;

    function  SSL_CTX_set_tmp_dh(ctx:PSSL_CTX;dh : Pointer) : clong;

    function  SSL_CTX_set_tmp_ecdh(ctx:PSSL_CTX;ecdh : Pointer) : clong;

    function  SSL_CTX_set_dh_auto(ctx:PSSL_CTX;onoff : clong) : clong;

    function  SSL_set_dh_auto(s : PSSL;onoff : clong) : clong;

    function  SSL_set_tmp_dh(ssl : PSSL;dh : Pointer) : clong;

    function  SSL_set_tmp_ecdh(ssl : PSSL;ecdh : Pointer) : clong;

    function  SSL_CTX_add_extra_chain_cert(ctx:PSSL_CTX;x509 : Pointer) : clong;

    function  SSL_CTX_get_extra_chain_certs(ctx:PSSL_CTX;px509 : Pointer) : clong;

    function  SSL_CTX_get_extra_chain_certs_only(ctx:PSSL_CTX;px509 : Pointer) : clong;

    function  SSL_CTX_clear_extra_chain_certs(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_set0_chain(ctx : PSSL_CTX;sk : Pointer) : clong;

    function  SSL_CTX_set1_chain(ctx : PSSL_CTX;sk : Pointer) : clong;

    function  SSL_CTX_add0_chain_cert(ctx:PSSL_CTX;x509 : Pointer) : clong;

    function  SSL_CTX_add1_chain_cert(ctx:PSSL_CTX;x509 : Pointer) : clong;

    function  SSL_CTX_get0_chain_certs(ctx:PSSL_CTX;px509 : Pointer) : clong;

    function  SSL_CTX_clear_chain_certs(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_build_cert_chain(ctx:PSSL_CTX;flags : clong) : clong;

    function  SSL_CTX_select_current_cert(ctx:PSSL_CTX;x509 : Pointer) : clong;

    function  SSL_CTX_set_current_cert(ctx:PSSL_CTX;op : clong) : clong;

    function  SSL_CTX_set0_verify_cert_store(ctx:PSSL_CTX;st : Pointer) : clong;

    function  SSL_CTX_set1_verify_cert_store(ctx:PSSL_CTX;st : Pointer) : clong;

    function  SSL_CTX_set0_chain_cert_store(ctx:PSSL_CTX;st : Pointer) : clong;

    function  SSL_CTX_set1_chain_cert_store(ctx:PSSL_CTX;st : Pointer) : clong;

    function  SSL_set0_chain(ctx:PSSL;sk : Pointer) : clong;

    function  SSL_set1_chain(ctx:PSSL;sk : Pointer) : clong;

    function  SSL_add0_chain_cert(ctx:PSSL;x509 : Pointer) : clong;

    function  SSL_add1_chain_cert(ctx:PSSL;x509 : Pointer) : clong;

    function  SSL_get0_chain_certs(ctx:PSSL;px509 : Pointer) : clong;

    function  SSL_clear_chain_certs(ctx : PSSL) : clong;

    function  SSL_build_cert_chain(s : PSSL;flags : clong) : clong;

    function  SSL_select_current_cert(ctx:PSSL;x509 : Pointer) : clong;

    function  SSL_set_current_cert(ctx:PSSL;op : clong) : clong;

    function  SSL_set0_verify_cert_store(s:PSSL;st : Pointer) : clong;

    function  SSL_set1_verify_cert_store(s:PSSL;st : Pointer) : clong;

    function  SSL_set0_chain_cert_store(s:PSSL;st : Pointer) : clong;

    function  SSL_set1_chain_cert_store(s:PSSL;st : Pointer) : clong;

    function  SSL_get1_curves(ctx:PSSL;s : Pointer) : clong;

    function  SSL_CTX_set1_curves(ctx:PSSL_CTX;clist:Pointer;clistlen : clong) : clong;

    function  SSL_CTX_set1_curves_list(ctx:PSSL_CTX;s : Pointer) : clong;

    function  SSL_set1_curves(ctx:PSSL;clist:Pointer;clistlen : clong) : clong;

    function  SSL_set1_curves_list(ctx:PSSL;s : Pointer) : clong;

    function  SSL_get_shared_curve(s:PSSL;n : clong) : clong;

    function  SSL_CTX_set1_sigalgs(ctx:PSSL_CTX;slist:Pointer;slistlen : clong) : clong;

    function  SSL_CTX_set1_sigalgs_list(ctx:PSSL_CTX;s : Pointer) : clong;

    function  SSL_set1_sigalgs(ctx:PSSL;slist:Pointer;slistlen : clong) : clong;

    function  SSL_set1_sigalgs_list(ctx:PSSL;s : Pointer) : clong;

    function  SSL_CTX_set1_client_sigalgs(ctx:PSSL_CTX;slist:Pointer;slistlen : clong) : clong;

    function  SSL_CTX_set1_client_sigalgs_list(ctx:PSSL_CTX;s : Pointer) : clong;

    function  SSL_set1_client_sigalgs(ctx:PSSL;slist:Pointer;slistlen : clong) : clong;

    function  SSL_set1_client_sigalgs_list(ctx:PSSL;s : Pointer) : clong;

    function  SSL_get0_certificate_types(s:PSSL;clist : Pointer) : clong;

    function  SSL_CTX_set1_client_certificate_types(ctx:PSSL_CTX;clist:Pointer;clistlen : clong) : clong;

    function  SSL_set1_client_certificate_types(s:PSSL;clist:Pointer;clistlen : clong) : clong;

    function  SSL_get_peer_signature_nid(s:PSSL;pn : Pointer) : clong;

    function  SSL_get_server_tmp_key(s:PSSL;pk : Pointer) : clong;

    function  SSL_get0_raw_cipherlist(s:PSSL;plst : Pointer) : clong;

    function  SSL_get0_ec_point_formats(s:PSSL;plst : Pointer) : clong;

    function  SSL_CTX_set_min_proto_version(ctx:PSSL_CTX;version : clong) : clong;

    function  SSL_CTX_set_max_proto_version(ctx:PSSL_CTX;version : clong) : clong;

    function  SSL_CTX_get_min_proto_version(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_get_max_proto_version(ctx : PSSL_CTX) : clong;

    function  SSL_set_min_proto_version(s:PSSL;version : clong) : clong;

    function  SSL_set_max_proto_version(s:PSSL;version : clong) : clong;

    function  SSL_get_min_proto_version(s : PSSL) : clong;

    function  SSL_get_max_proto_version(s : PSSL) : clong;

type
 TSSL_cert_cb=function  (ssl:PSSL; arg:pointer):cint;cdecl;
 TSSL_CTX_cert_verify_cb=function  (para1:PX509_STORE_CTX; para2:pointer):cint;cdecl;
 TSSL_CTX_srp_client_pwd_cb=function  (para1:PSSL; para2:pointer):pbyte;cdecl;
 TSSL_CTX_srp_verify_param_cb=function  (para1:PSSL; para2:pointer):cint;cdecl;
 TSSL_CTX_srp_username_cb=function  (para1:PSSL; para2:pcint; para3:pointer):cint;cdecl;

 TSslMethod = function:PSSL_METHOD; cdecl;

function  BIO_f_ssl:PBIO_METHOD;cdecl; external DLLSSLName;
function  BIO_new_ssl(ctx:PSSL_CTX; client:cint):PBIO;cdecl; external DLLSSLName;
function  BIO_new_ssl_connect(ctx:PSSL_CTX):PBIO;cdecl; external DLLSSLName;
function  BIO_new_buffer_ssl_connect(ctx:PSSL_CTX):PBIO;cdecl; external DLLSSLName;
function  BIO_ssl_copy_session_id(_to:PBIO; from:PBIO):cint;cdecl; external DLLSSLName;
procedure BIO_ssl_shutdown(ssl_bio:PBIO);cdecl; external DLLSSLName;
function  SSL_CTX_set_cipher_list(para1:PSSL_CTX; str:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_CTX_new(meth:PSSL_METHOD):PSSL_CTX;cdecl; external DLLSSLName;
function  SSL_CTX_up_ref(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
procedure SSL_CTX_free(para1:PSSL_CTX);cdecl; external DLLSSLName;
function  SSL_CTX_set_timeout(ctx:PSSL_CTX; t:clong):clong;cdecl; external DLLSSLName;
function  SSL_CTX_get_timeout(ctx:PSSL_CTX):clong;cdecl; external DLLSSLName;
function  SSL_CTX_get_cert_store(para1:PSSL_CTX):PX509_STORE;cdecl; external DLLSSLName;
procedure SSL_CTX_set_cert_store(para1:PSSL_CTX; para2:PX509_STORE);cdecl; external DLLSSLName;
function  SSL_want(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_clear(s:PSSL):cint;cdecl; external DLLSSLName;
procedure SSL_CTX_flush_sessions(ctx:PSSL_CTX; tm:clong);cdecl; external DLLSSLName;
function  SSL_get_current_cipher(s:PSSL):PSSL_CIPHER;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_bits(c:PSSL_CIPHER; alg_bits:pcint):cint;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_version(c:PSSL_CIPHER):pbyte;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_name(c:PSSL_CIPHER):pbyte;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_id(c:PSSL_CIPHER):uint32;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_kx_nid(c:PSSL_CIPHER):cint;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_auth_nid(c:PSSL_CIPHER):cint;cdecl; external DLLSSLName;
function  SSL_CIPHER_is_aead(c:PSSL_CIPHER):cint;cdecl; external DLLSSLName;
function  SSL_get_fd(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_get_rfd(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_get_wfd(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_get_cipher_list(s:PSSL; n:cint):pbyte;cdecl; external DLLSSLName;
function  SSL_get_shared_ciphers(s:PSSL; buf:pbyte; len:cint):pbyte;cdecl; external DLLSSLName;
function  SSL_get_read_ahead(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_pending(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_has_pending(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_set_fd(s:PSSL; fd:cint):cint;cdecl; external DLLSSLName;
function  SSL_set_rfd(s:PSSL; fd:cint):cint;cdecl; external DLLSSLName;
function  SSL_set_wfd(s:PSSL; fd:cint):cint;cdecl; external DLLSSLName;
procedure SSL_set0_rbio(s:PSSL; rbio:PBIO);cdecl; external DLLSSLName;
procedure SSL_set0_wbio(s:PSSL; wbio:PBIO);cdecl; external DLLSSLName;
procedure SSL_set_bio(s:PSSL; rbio:PBIO; wbio:PBIO);cdecl; external DLLSSLName;
function  SSL_get_rbio(s:PSSL):PBIO;cdecl; external DLLSSLName;
function  SSL_get_wbio(s:PSSL):PBIO;cdecl; external DLLSSLName;
function  SSL_set_cipher_list(s:PSSL; str:pbyte):cint;cdecl; external DLLSSLName;
procedure SSL_set_read_ahead(s:PSSL; yes:cint);cdecl; external DLLSSLName;
function  SSL_get_verify_mode(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_get_verify_depth(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_get_verify_callback(s:PSSL):TSSL_verify_cb;cdecl; external DLLSSLName;
procedure SSL_set_verify(s:PSSL; mode:cint; callback:TSSL_verify_cb);cdecl; external DLLSSLName;
procedure SSL_set_verify_depth(s:PSSL; depth:cint);cdecl; external DLLSSLName;
procedure SSL_set_cert_cb(s:PSSL; cb:TSSL_cert_cb; arg:pointer);cdecl; external DLLSSLName;
function  SSL_use_RSAPrivateKey(ssl:PSSL; rsa:PRSA):cint;cdecl; external DLLSSLName;
function  SSL_use_RSAPrivateKey_ASN1(ssl:PSSL; d:pbyte; len:clong):cint;cdecl; external DLLSSLName;
function  SSL_use_PrivateKey(ssl:PSSL; pkey:PEVP_PKEY):cint;cdecl; external DLLSSLName;
function  SSL_use_PrivateKey_ASN1(pk:cint; ssl:PSSL; d:pbyte; len:clong):cint;cdecl; external DLLSSLName;
function  SSL_use_certificate(ssl:PSSL; x:PX509):cint;cdecl; external DLLSSLName;
function  SSL_use_certificate_ASN1(ssl:PSSL; d:pbyte; len:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_serverinfo(ctx:PSSL_CTX; serverinfo:pbyte; serverinfo_length:size_t):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_serverinfo_file(ctx:PSSL_CTX; _file:PChar):cint;cdecl; external DLLSSLName;
function  SSL_use_RSAPrivateKey_file(ssl:PSSL; _file:PChar; _type:cint):cint;cdecl; external DLLSSLName;
function  SSL_use_PrivateKey_file(ssl:PSSL; _file:PChar; _type:cint):cint;cdecl; external DLLSSLName;
function  SSL_use_certificate_file(ssl:PSSL; _file:PChar; _type:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_RSAPrivateKey_file(ctx:PSSL_CTX; _file:PChar; _type:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_PrivateKey_file(ctx:PSSL_CTX; _file:PChar; _type:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_certificate_file(ctx:PSSL_CTX; _file:PChar; _type:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_certificate_chain_file(ctx:PSSL_CTX; _file:PChar):cint;cdecl; external DLLSSLName;
function  SSL_use_certificate_chain_file(ssl:PSSL; _file:PChar):cint;cdecl; external DLLSSLName;
function  SSL_add_file_cert_subjects_to_stack(stackCAs:PX509_NAME; _file:PChar):cint;cdecl; external DLLSSLName;
function  SSL_add_dir_cert_subjects_to_stack(stackCAs:PX509_NAME; dir:pbyte):cint;cdecl; external DLLSSLName;

    function  SSL_load_error_strings : cint;

function  SSL_state_string(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_rstate_string(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_state_string_long(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_rstate_string_long(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_SESSION_get_time(s:PSSL_SESSION):clong;cdecl; external DLLSSLName;
function  SSL_SESSION_set_time(s:PSSL_SESSION; t:clong):clong;cdecl; external DLLSSLName;
function  SSL_SESSION_get_timeout(s:PSSL_SESSION):clong;cdecl; external DLLSSLName;
function  SSL_SESSION_set_timeout(s:PSSL_SESSION; t:clong):clong;cdecl; external DLLSSLName;
function  SSL_SESSION_get_protocol_version(s:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_get0_hostname(s:PSSL_SESSION):pbyte;cdecl; external DLLSSLName;
function  SSL_SESSION_get0_cipher(s:PSSL_SESSION):PSSL_CIPHER;cdecl; external DLLSSLName;
function  SSL_SESSION_has_ticket(s:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_get_ticket_lifetime_hint(s:PSSL_SESSION):culong;cdecl; external DLLSSLName;
procedure SSL_SESSION_get0_ticket(s:PSSL_SESSION; tick:Ppbyte; len:Psize_t);cdecl; external DLLSSLName;
function  SSL_copy_session_id(_to:PSSL; from:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_get0_peer(s:PSSL_SESSION):PX509;cdecl; external DLLSSLName;
function  SSL_SESSION_set1_id_context(s:PSSL_SESSION; sid_ctx:pbyte; sid_ctx_len:cuint):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_set1_id(s:PSSL_SESSION; sid:pbyte; sid_len:cuint):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_new:PSSL_SESSION;cdecl; external DLLSSLName;
function  SSL_SESSION_get_id(s:PSSL_SESSION; len:pcuint):pbyte;cdecl; external DLLSSLName;
function  SSL_SESSION_get0_id_context(s:PSSL_SESSION; len:pcuint):pbyte;cdecl; external DLLSSLName;
function  SSL_SESSION_get_compress_id(s:PSSL_SESSION):cuint;cdecl; external DLLSSLName;
//function  SSL_SESSION_print_fp(fp:PFILE; ses:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_print(fp:PBIO; ses:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_print_keylog(bp:PBIO; x:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_up_ref(ses:PSSL_SESSION):cint;cdecl; external DLLSSLName;
procedure SSL_SESSION_free(ses:PSSL_SESSION);cdecl; external DLLSSLName;
function  i2d_SSL_SESSION(_in:PSSL_SESSION; pp:Ppbyte):cint;cdecl; external DLLSSLName;
function  SSL_set_session(_to:PSSL; session:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_CTX_add_session(s:PSSL_CTX; c:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_CTX_remove_session(para1:PSSL_CTX; c:PSSL_SESSION):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_generate_session_id(para1:PSSL_CTX; para2:TGEN_SESSION_CB):cint;cdecl; external DLLSSLName;
function  SSL_set_generate_session_id(para1:PSSL; para2:TGEN_SESSION_CB):cint;cdecl; external DLLSSLName;
function  SSL_has_matching_session_id(ssl:PSSL; id:pbyte; id_len:cuint):cint;cdecl; external DLLSSLName;
function  d2i_SSL_SESSION(a:PPSSL_SESSION; pp:Ppbyte; length:clong):PSSL_SESSION;cdecl; external DLLSSLName;
function  SSL_get_peer_certificate(s:PSSL):PX509;cdecl; external DLLSSLName;
function  SSL_CTX_get_verify_mode(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_CTX_get_verify_depth(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_CTX_get_verify_callback(ctx:PSSL_CTX):TSSL_verify_cb;cdecl; external DLLSSLName;
procedure SSL_CTX_set_verify(ctx:PSSL_CTX; mode:cint; callback:TSSL_verify_cb);cdecl; external DLLSSLName;
procedure SSL_CTX_set_verify_depth(ctx:PSSL_CTX; depth:cint);cdecl; external DLLSSLName;
procedure SSL_CTX_set_cert_verify_callback(ctx:PSSL_CTX; cb:TSSL_CTX_cert_verify_cb; arg:pointer);cdecl; external DLLSSLName;
procedure SSL_CTX_set_cert_cb(c:PSSL_CTX; cb:TSSL_cert_cb; arg:pointer);cdecl; external DLLSSLName;
function  SSL_CTX_use_RSAPrivateKey(ctx:PSSL_CTX; rsa:PRSA):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_RSAPrivateKey_ASN1(ctx:PSSL_CTX; d:pbyte; len:clong):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_PrivateKey(ctx:PSSL_CTX; pkey:PEVP_PKEY):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_PrivateKey_ASN1(pk:cint; ctx:PSSL_CTX; d:pbyte; len:clong):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_certificate(ctx:PSSL_CTX; x:PX509):cint;cdecl; external DLLSSLName;
function  SSL_CTX_use_certificate_ASN1(ctx:PSSL_CTX; len:cint; d:pbyte):cint;cdecl; external DLLSSLName;
procedure SSL_CTX_set_default_passwd_cb(ctx:PSSL_CTX; cb:Ppem_password_cb);cdecl; external DLLSSLName;
procedure SSL_CTX_set_default_passwd_cb_userdata(ctx:PSSL_CTX; u:pointer);cdecl; external DLLSSLName;
function  SSL_CTX_get_default_passwd_cb(ctx:PSSL_CTX):Ppem_password_cb;cdecl; external DLLSSLName;
function  SSL_CTX_get_default_passwd_cb_userdata(ctx:PSSL_CTX):pointer;cdecl; external DLLSSLName;
procedure SSL_set_default_passwd_cb(s:PSSL; cb:Ppem_password_cb);cdecl; external DLLSSLName;
procedure SSL_set_default_passwd_cb_userdata(s:PSSL; u:pointer);cdecl; external DLLSSLName;
function  SSL_get_default_passwd_cb(s:PSSL):Ppem_password_cb;cdecl; external DLLSSLName;
function  SSL_get_default_passwd_cb_userdata(s:PSSL):pointer;cdecl; external DLLSSLName;
function  SSL_CTX_check_private_key(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_check_private_key(ctx:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_session_id_context(ctx:PSSL_CTX; sid_ctx:pbyte; sid_ctx_len:cuint):cint;cdecl; external DLLSSLName;
function  SSL_new(ctx:PSSL_CTX):PSSL;cdecl; external DLLSSLName;
function  SSL_up_ref(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_is_dtls(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_set_session_id_context(ssl:PSSL; sid_ctx:pbyte; sid_ctx_len:cuint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_purpose(s:PSSL_CTX; purpose:cint):cint;cdecl; external DLLSSLName;
function  SSL_set_purpose(s:PSSL; purpose:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_trust(s:PSSL_CTX; trust:cint):cint;cdecl; external DLLSSLName;
function  SSL_set_trust(s:PSSL; trust:cint):cint;cdecl; external DLLSSLName;
function  SSL_set1_host(s:PSSL; hostname:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_add1_host(s:PSSL; hostname:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_get0_peername(s:PSSL):pbyte;cdecl; external DLLSSLName;
procedure SSL_set_hostflags(s:PSSL; flags:cuint);cdecl; external DLLSSLName;
function  SSL_CTX_dane_enable(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_CTX_dane_mtype_set(ctx:PSSL_CTX; md:PEVP_MD; mtype:uint8; ord:uint8):cint;cdecl; external DLLSSLName;
function  SSL_dane_enable(s:PSSL; basedomain:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_dane_tlsa_add(s:PSSL; usage:uint8; selector:uint8; mtype:uint8; data:pbyte;
               dlen:size_t):cint;cdecl; external DLLSSLName;
function  SSL_get0_dane_authority(s:PSSL; mcert:PPX509; mspki:PPEVP_PKEY):cint;cdecl; external DLLSSLName;
function  SSL_get0_dane(ssl:PSSL):PSSL_DANE;cdecl; external DLLSSLName;
function  SSL_CTX_dane_set_flags(ctx:PSSL_CTX; flags:culong):culong;cdecl; external DLLSSLName;
function  SSL_CTX_dane_clear_flags(ctx:PSSL_CTX; flags:culong):culong;cdecl; external DLLSSLName;
function  SSL_dane_set_flags(ssl:PSSL; flags:culong):culong;cdecl; external DLLSSLName;
function  SSL_dane_clear_flags(ssl:PSSL; flags:culong):culong;cdecl; external DLLSSLName;
function  SSL_CTX_set1_param(ctx:PSSL_CTX; vpm:PX509_VERIFY_PARAM):cint;cdecl; external DLLSSLName;
function  SSL_set1_param(ssl:PSSL; vpm:PX509_VERIFY_PARAM):cint;cdecl; external DLLSSLName;
function  SSL_CTX_get0_param(ctx:PSSL_CTX):PX509_VERIFY_PARAM;cdecl; external DLLSSLName;
function  SSL_get0_param(ssl:PSSL):PX509_VERIFY_PARAM;cdecl; external DLLSSLName;
function  SSL_CTX_set_srp_username(ctx:PSSL_CTX; name:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_srp_password(ctx:PSSL_CTX; password:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_srp_strength(ctx:PSSL_CTX; strength:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_srp_client_pwd_callback(ctx:PSSL_CTX; cb:TSSL_CTX_srp_client_pwd_cb):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_srp_verify_param_callback(ctx:PSSL_CTX; cb:TSSL_CTX_srp_verify_param_cb):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_srp_username_callback(ctx:PSSL_CTX; cb:TSSL_CTX_srp_username_cb):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_srp_cb_arg(ctx:PSSL_CTX; arg:pointer):cint;cdecl; external DLLSSLName;
function  SSL_set_srp_server_param(s:PSSL; N:PBIGNUM; g:PBIGNUM; sa:PBIGNUM; v:PBIGNUM; 
               info:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_set_srp_server_param_pw(s:PSSL; user:pbyte; pass:pbyte; grp:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_get_srp_g(s:PSSL):PBIGNUM;cdecl; external DLLSSLName;
function  SSL_get_srp_N(s:PSSL):PBIGNUM;cdecl; external DLLSSLName;
function  SSL_get_srp_username(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_get_srp_userinfo(s:PSSL):pbyte;cdecl; external DLLSSLName;
procedure SSL_certs_clear(s:PSSL);cdecl; external DLLSSLName;
procedure SSL_free(ssl:PSSL);cdecl; external DLLSSLName;
function  SSL_waiting_for_async(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_get_all_async_fds(s:PSSL; fds:pcint; numfds:Psize_t):cint;cdecl; external DLLSSLName;
function  SSL_get_changed_async_fds(s:PSSL; addfd:pcint; numaddfds:Psize_t; delfd:pcint; numdelfds:Psize_t):cint;cdecl; external DLLSSLName;
function  SSL_accept(ssl:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_connect(ssl:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_read(ssl:PSSL; buf:pointer; num:cint):cint;cdecl; external DLLSSLName;
function  SSL_peek(ssl:PSSL; buf:pointer; num:cint):cint;cdecl; external DLLSSLName;
function  SSL_write(ssl:PSSL; buf:pointer; num:cint):cint;cdecl; external DLLSSLName;
function  SSL_ctrl(ssl:PSSL; cmd:cint; larg:clong; parg:pointer):clong;cdecl; external DLLSSLName;
function  SSL_callback_ctrl(para1:PSSL; para2:cint; para3:Tcprocedure ):clong;cdecl; external DLLSSLName;
function  SSL_CTX_ctrl(ctx:PSSL_CTX; cmd:cint; larg:clong; parg:pointer):clong;cdecl; external DLLSSLName;
function  SSL_CTX_callback_ctrl(para1:PSSL_CTX; para2:cint; para3:Tcprocedure ):clong;cdecl; external DLLSSLName;
function  SSL_get_error(s:PSSL; ret_code:cint):cint;cdecl; external DLLSSLName;
function  SSL_get_version(s:PSSL):pbyte;cdecl; external DLLSSLName;
function  SSL_CTX_set_ssl_version(ctx:PSSL_CTX; meth:PSSL_METHOD):cint;cdecl; external DLLSSLName;

function  SSLv23_server_method:PSSL_METHOD;cdecl;
function  SSLv23_client_method:PSSL_METHOD;cdecl;
function  SSLv23_method:PSSL_METHOD;cdecl;

function  SSLv3_server_method:PSSL_METHOD;cdecl;
function  SSLv3_client_method:PSSL_METHOD;cdecl;
function  SSLv3_method:PSSL_METHOD;cdecl;

function  TLS_server_method:PSSL_METHOD;cdecl;
function  TLS_client_method:PSSL_METHOD;cdecl;
function  TLS_method:PSSL_METHOD;cdecl;

function  TLSv1_1_server_method:PSSL_METHOD;cdecl;
function  TLSv1_1_client_method:PSSL_METHOD;cdecl;
function  TLSv1_1_method:PSSL_METHOD;cdecl;

function  TLSv1_2_server_method:PSSL_METHOD;cdecl;
function  TLSv1_2_client_method:PSSL_METHOD;cdecl;
function  TLSv1_2_method:PSSL_METHOD;cdecl;

function  TLSv1_server_method:PSSL_METHOD;cdecl;
function  TLSv1_client_method:PSSL_METHOD;cdecl;
function  TLSv1_method:PSSL_METHOD;cdecl;

function  DTLS_server_method:PSSL_METHOD;cdecl;
function  DTLS_client_method:PSSL_METHOD;cdecl;
function  DTLS_method:PSSL_METHOD;cdecl;

function  DTLSv1_2_server_method:PSSL_METHOD;cdecl;
function  DTLSv1_2_client_method:PSSL_METHOD;cdecl;
function  DTLSv1_2_method:PSSL_METHOD;cdecl;

function  DTLSv1_server_method:PSSL_METHOD;cdecl;
function  DTLSv1_client_method:PSSL_METHOD;cdecl;
function  DTLSv1_method:PSSL_METHOD;cdecl;

function  SSL_do_handshake(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_renegotiate(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_renegotiate_abbreviated(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_renegotiate_pending(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_shutdown(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_CTX_get_ssl_method(ctx:PSSL_CTX):PSSL_METHOD;cdecl; external DLLSSLName;
function  SSL_get_ssl_method(s:PSSL):PSSL_METHOD;cdecl; external DLLSSLName;
function  SSL_set_ssl_method(s:PSSL; method:PSSL_METHOD):cint;cdecl; external DLLSSLName;
function  SSL_alert_type_string_long(value:cint):pbyte;cdecl; external DLLSSLName;
function  SSL_alert_type_string(value:cint):pbyte;cdecl; external DLLSSLName;
function  SSL_alert_desc_string_long(value:cint):pbyte;cdecl; external DLLSSLName;
function  SSL_alert_desc_string(value:cint):pbyte;cdecl; external DLLSSLName;
procedure SSL_set_client_CA_list(s:PSSL; name_list:PX509_NAME);cdecl; external DLLSSLName;
procedure SSL_CTX_set_client_CA_list(ctx:PSSL_CTX; name_list:PX509_NAME);cdecl; external DLLSSLName;
function  SSL_add_client_CA(ssl:PSSL; x:PX509):cint;cdecl; external DLLSSLName;
function  SSL_CTX_add_client_CA(ctx:PSSL_CTX; x:PX509):cint;cdecl; external DLLSSLName;
procedure SSL_set_connect_state(s:PSSL);cdecl; external DLLSSLName;
procedure SSL_set_accept_state(s:PSSL);cdecl; external DLLSSLName;
function  SSL_get_default_timeout(s:PSSL):clong;cdecl; external DLLSSLName;

    function  SSL_library_init : cint;

function  SSL_CIPHER_description(para1:PSSL_CIPHER; buf:pbyte; size:cint):pbyte;cdecl; external DLLSSLName;
function  SSL_dup(ssl:PSSL):PSSL;cdecl; external DLLSSLName;
function  SSL_get_certificate(ssl:PSSL):PX509;cdecl; external DLLSSLName;
function  SSL_CTX_get0_certificate(ctx:PSSL_CTX):PX509;cdecl; external DLLSSLName;
function  SSL_CTX_get0_privatekey(ctx:PSSL_CTX):PEVP_PKEY;cdecl; external DLLSSLName;
procedure SSL_CTX_set_quiet_shutdown(ctx:PSSL_CTX; mode:cint);cdecl; external DLLSSLName;
function  SSL_CTX_get_quiet_shutdown(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
procedure SSL_set_quiet_shutdown(ssl:PSSL; mode:cint);cdecl; external DLLSSLName;
function  SSL_get_quiet_shutdown(ssl:PSSL):cint;cdecl; external DLLSSLName;
procedure SSL_set_shutdown(ssl:PSSL; mode:cint);cdecl; external DLLSSLName;
function  SSL_get_shutdown(ssl:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_version(ssl:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_client_version(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_default_verify_paths(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_default_verify_dir(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_default_verify_file(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_CTX_load_verify_locations(ctx:PSSL_CTX; CAfile:pbyte; CApath:pbyte):cint;cdecl; external DLLSSLName;

function  SSL_get_session(ssl:PSSL):PSSL_SESSION;cdecl; external DLLSSLName;
function  SSL_get1_session(ssl:PSSL):PSSL_SESSION;cdecl; external DLLSSLName;
function  SSL_get_SSL_CTX(ssl:PSSL):PSSL_CTX;cdecl; external DLLSSLName;
function  SSL_set_SSL_CTX(ssl:PSSL; ctx:PSSL_CTX):PSSL_CTX;cdecl; external DLLSSLName;
procedure SSL_set_info_callback(ssl:PSSL; cb:Tssl_ctx_info_cb);cdecl; external DLLSSLName;
function  SSL_get_info_callback(ssl:PSSL):Tssl_ctx_info_cb;cdecl; external DLLSSLName;
function  SSL_get_state(ssl:PSSL):TOSSL_HANDSHAKE_STATE;cdecl; external DLLSSLName;
procedure SSL_set_verify_result(ssl:PSSL; v:clong);cdecl; external DLLSSLName;
function  SSL_get_verify_result(ssl:PSSL):clong;cdecl; external DLLSSLName;
function  SSL_get_client_random(ssl:PSSL;_out:pbyte; outlen:size_t):size_t;cdecl; external DLLSSLName;
function  SSL_get_server_random(ssl:PSSL;_out:pbyte; outlen:size_t):size_t;cdecl; external DLLSSLName;
function  SSL_SESSION_get_master_key(ssl:PSSL_SESSION;_out:pbyte; outlen:size_t):size_t;cdecl; external DLLSSLName;

    function  SSL_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  SSL_set_ex_data(ssl:PSSL; idx:cint; data:pointer):cint;cdecl; external DLLSSLName;
function  SSL_get_ex_data(ssl:PSSL; idx:cint):pointer;cdecl; external DLLSSLName;

    function  SSL_SESSION_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  SSL_SESSION_set_ex_data(ss:PSSL_SESSION; idx:cint; data:pointer):cint;cdecl; external DLLSSLName;
function  SSL_SESSION_get_ex_data(ss:PSSL_SESSION; idx:cint):pointer;cdecl; external DLLSSLName;

    function  SSL_CTX_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint;

function  SSL_CTX_set_ex_data(ssl:PSSL_CTX; idx:cint; data:pointer):cint;cdecl; external DLLSSLName;
function  SSL_CTX_get_ex_data(ssl:PSSL_CTX; idx:cint):pointer;cdecl; external DLLSSLName;
function  SSL_get_ex_data_X509_STORE_CTX_idx:cint;cdecl; external DLLSSLName;

    function  SSL_CTX_sess_set_cache_size(ctx:PSSL_CTX;t : clong) : clong;

    function  SSL_CTX_sess_get_cache_size(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_set_session_cache_mode(ctx:PSSL_CTX;m : clong) : clong;

    function  SSL_CTX_get_session_cache_mode(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_get_default_read_ahead(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_set_default_read_ahead(ctx:PSSL_CTX;m : clong) : clong;

    function  SSL_CTX_get_read_ahead(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_set_read_ahead(ctx:PSSL_CTX;m : clong) : clong;

    function  SSL_CTX_get_max_cert_list(ctx : PSSL_CTX) : clong;

    function  SSL_CTX_set_max_cert_list(ctx:PSSL_CTX;m : clong) : clong;

    function  SSL_get_max_cert_list(ssl : PSSL) : clong;

    function  SSL_set_max_cert_list(ssl:PSSL;m : clong) : clong;

    function  SSL_CTX_set_max_send_fragment(ctx:PSSL_CTX;m : clong) : clong;

    function  SSL_set_max_send_fragment(ssl:PSSL;m : clong) : clong;

    function  SSL_CTX_set_split_send_fragment(ctx:PSSL_CTX;m : clong) : clong;

    function  SSL_set_split_send_fragment(ssl:PSSL;m : clong) : clong;

    function  SSL_CTX_set_max_pipelines(ctx:PSSL_CTX;m : clong) : clong;

    function  SSL_set_max_pipelines(ssl:PSSL;m : clong) : clong;

type
 TSSL_CTX_tmp_dh_cb=function  (ssl:PSSL; is_export:cint; keylength:cint):PDH;cdecl;
 TSSL_CTX_not_resumable_session_cb=function  (ssl:PSSL; is_forward_secure:cint):cint;cdecl;

procedure SSL_CTX_set_default_read_buffer_len(ctx:PSSL_CTX; len:size_t);cdecl; external DLLSSLName;
procedure SSL_set_default_read_buffer_len(s:PSSL; len:size_t);cdecl; external DLLSSLName;
procedure SSL_CTX_set_tmp_dh_callback(ctx:PSSL_CTX; dh:TSSL_CTX_tmp_dh_cb);cdecl; external DLLSSLName;
procedure SSL_set_tmp_dh_callback(ssl:PSSL; dh:TSSL_CTX_tmp_dh_cb);cdecl; external DLLSSLName;
function  SSL_get_current_compression(s:PSSL):PCOMP_METHOD;cdecl; external DLLSSLName;
function  SSL_get_current_expansion(s:PSSL):PCOMP_METHOD;cdecl; external DLLSSLName;
function  SSL_COMP_get_name(comp:PCOMP_METHOD):pbyte;cdecl; external DLLSSLName;
function  SSL_COMP_get0_name(comp:PSSL_COMP):pbyte;cdecl; external DLLSSLName;
function  SSL_COMP_get_id(comp:PSSL_COMP):cint;cdecl; external DLLSSLName;
function  SSL_CIPHER_find(ssl:PSSL; ptr:pbyte):PSSL_CIPHER;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_cipher_nid(c:PSSL_CIPHER):cint;cdecl; external DLLSSLName;
function  SSL_CIPHER_get_digest_nid(c:PSSL_CIPHER):cint;cdecl; external DLLSSLName;
function  SSL_set_session_ticket_ext(s:PSSL; ext_data:pointer; ext_len:cint):cint;cdecl; external DLLSSLName;
function  SSL_set_session_ticket_ext_cb(s:PSSL; cb:Ttls_session_ticket_ext_cb_fn; arg:pointer):cint;cdecl; external DLLSSLName;
function  SSL_set_session_secret_cb(s:PSSL; tls_session_secret_cb:Ttls_session_secret_cb_fn; arg:pointer):cint;cdecl; external DLLSSLName;
procedure SSL_CTX_set_not_resumable_session_callback(ctx:PSSL_CTX; cb:TSSL_CTX_not_resumable_session_cb);cdecl; external DLLSSLName;
procedure SSL_set_not_resumable_session_callback(ssl:PSSL; cb:TSSL_CTX_not_resumable_session_cb);cdecl; external DLLSSLName;

    function  SSL_cache_hit(s:PSSL):cint;

function  SSL_session_reused(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_is_server(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_CONF_CTX_new:PSSL_CONF_CTX;cdecl; external DLLSSLName;
function  SSL_CONF_CTX_finish(cctx:PSSL_CONF_CTX):cint;cdecl; external DLLSSLName;
procedure SSL_CONF_CTX_free(cctx:PSSL_CONF_CTX);cdecl; external DLLSSLName;
function  SSL_CONF_CTX_set_flags(cctx:PSSL_CONF_CTX; flags:cuint):cuint;cdecl; external DLLSSLName;
function  SSL_CONF_CTX_clear_flags(cctx:PSSL_CONF_CTX; flags:cuint):cuint;cdecl; external DLLSSLName;
function  SSL_CONF_CTX_set1_prefix(cctx:PSSL_CONF_CTX; pre:pbyte):cint;cdecl; external DLLSSLName;
procedure SSL_CONF_CTX_set_ssl(cctx:PSSL_CONF_CTX; ssl:PSSL);cdecl; external DLLSSLName;
procedure SSL_CONF_CTX_set_ssl_ctx(cctx:PSSL_CONF_CTX; ctx:PSSL_CTX);cdecl; external DLLSSLName;
function  SSL_CONF_cmd(cctx:PSSL_CONF_CTX; cmd:pbyte; value:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_CONF_cmd_argv(cctx:PSSL_CONF_CTX; pargc:pcint; pargv:PPpbyte):cint;cdecl; external DLLSSLName;
function  SSL_CONF_cmd_value_type(cctx:PSSL_CONF_CTX; cmd:pbyte):cint;cdecl; external DLLSSLName;
procedure SSL_add_ssl_module;cdecl; external DLLSSLName;
function  SSL_config(s:PSSL; name:pbyte):cint;cdecl; external DLLSSLName;
function  SSL_CTX_config(ctx:PSSL_CTX; name:pbyte):cint;cdecl; external DLLSSLName;
procedure SSL_trace(write_p:cint; version:cint; content_type:cint; buf:pointer; len:size_t; 
                ssl:PSSL; arg:pointer);cdecl; external DLLSSLName;
function  SSL_CIPHER_standard_name(c:PSSL_CIPHER):pbyte;cdecl; external DLLSSLName;
function  DTLSv1_listen(s:PSSL; client:PBIO_ADDR):cint;cdecl; external DLLSSLName;

    type
      Tssl_ct_validation_cb = function  (ctx:PCT_POLICY_EVAL_CTX; scts:Pstack_st_SCT; arg:pointer):cint;cdecl;

function  SSL_set_ct_validation_callback(s:PSSL; callback:Tssl_ct_validation_cb; arg:pointer):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_ct_validation_callback(ctx:PSSL_CTX; callback:Tssl_ct_validation_cb; arg:pointer):cint;cdecl; external DLLSSLName;

    function  SSL_disable_ct(s : PSSL) : cint;

    function  SSL_CTX_disable_ct(ctx : PSSL_CTX) : cint;

function  SSL_enable_ct(s:PSSL; validation_mode:cint):cint;cdecl; external DLLSSLName;
function  SSL_CTX_enable_ct(ctx:PSSL_CTX; validation_mode:cint):cint;cdecl; external DLLSSLName;
function  SSL_ct_is_enabled(s:PSSL):cint;cdecl; external DLLSSLName;
function  SSL_CTX_ct_is_enabled(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_get0_peer_scts(s:PSSL):Pstack_st_SCT;cdecl; external DLLSSLName;
function  SSL_CTX_set_default_ctlog_list_file(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
function  SSL_CTX_set_ctlog_list_file(ctx:PSSL_CTX; path:pbyte):cint;cdecl; external DLLSSLName;
procedure SSL_CTX_set0_ctlog_store(ctx:PSSL_CTX; logs:PCTLOG_STORE);cdecl; external DLLSSLName;
function  SSL_CTX_get0_ctlog_store(ctx:PSSL_CTX):PCTLOG_STORE;cdecl; external DLLSSLName;

    const
      SSL_SECOP_OTHER_TYPE = $ffff0000;      
      SSL_SECOP_OTHER_NONE = 0;      
      SSL_SECOP_OTHER_CIPHER = 1 shl 16;      
      SSL_SECOP_OTHER_CURVE = 2 shl 16;      
      SSL_SECOP_OTHER_DH = 3 shl 16;      
      SSL_SECOP_OTHER_PKEY = 4 shl 16;      
      SSL_SECOP_OTHER_SIGALG = 5 shl 16;      
      SSL_SECOP_OTHER_CERT = 6 shl 16;      
      SSL_SECOP_PEER = $1000;      
      SSL_SECOP_CIPHER_SUPPORTED = 1 or SSL_SECOP_OTHER_CIPHER;      
      SSL_SECOP_CIPHER_SHARED = 2 or SSL_SECOP_OTHER_CIPHER;      
      SSL_SECOP_CIPHER_CHECK = 3 or SSL_SECOP_OTHER_CIPHER;      
      SSL_SECOP_CURVE_SUPPORTED = 4 or SSL_SECOP_OTHER_CURVE;      
      SSL_SECOP_CURVE_SHARED = 5 or SSL_SECOP_OTHER_CURVE;      
      SSL_SECOP_CURVE_CHECK = 6 or SSL_SECOP_OTHER_CURVE;      
      SSL_SECOP_TMP_DH = 7 or SSL_SECOP_OTHER_PKEY;      
      SSL_SECOP_VERSION = 9 or SSL_SECOP_OTHER_NONE;      
      SSL_SECOP_TICKET = 10 or SSL_SECOP_OTHER_NONE;      
      SSL_SECOP_SIGALG_SUPPORTED = 11 or SSL_SECOP_OTHER_SIGALG;      
      SSL_SECOP_SIGALG_SHARED = 12 or SSL_SECOP_OTHER_SIGALG;      
      SSL_SECOP_SIGALG_CHECK = 13 or SSL_SECOP_OTHER_SIGALG;      
      SSL_SECOP_SIGALG_MASK = 14 or SSL_SECOP_OTHER_SIGALG;      
      SSL_SECOP_COMPRESSION = 15 or SSL_SECOP_OTHER_NONE;      
      SSL_SECOP_EE_KEY = 16 or SSL_SECOP_OTHER_CERT;      
      SSL_SECOP_CA_KEY = 17 or SSL_SECOP_OTHER_CERT;      
      SSL_SECOP_CA_MD = 18 or SSL_SECOP_OTHER_CERT;      
      SSL_SECOP_PEER_EE_KEY = SSL_SECOP_EE_KEY or SSL_SECOP_PEER;      
      SSL_SECOP_PEER_CA_KEY = SSL_SECOP_CA_KEY or SSL_SECOP_PEER;      
      SSL_SECOP_PEER_CA_MD = SSL_SECOP_CA_MD or SSL_SECOP_PEER;      

type
 TSSL_security_cb=function  (s:PSSL; ctx:PSSL_CTX; op:cint; bits:cint; nid:cint; other:pointer; ex:pointer):cint;cdecl;

procedure SSL_set_security_level(s:PSSL; level:cint);cdecl; external DLLSSLName;
function  SSL_get_security_level(s:PSSL):cint;cdecl; external DLLSSLName;
procedure SSL_set_security_callback(s:PSSL; cb:TSSL_security_cb);cdecl; external DLLSSLName;
function  SSL_get_security_callback(s:PSSL):TSSL_security_cb;cdecl; external DLLSSLName;
procedure SSL_set0_security_ex_data(s:PSSL; ex:pointer);cdecl; external DLLSSLName;
function  SSL_get0_security_ex_data(s:PSSL):pointer;cdecl; external DLLSSLName;
procedure SSL_CTX_set_security_level(ctx:PSSL_CTX; level:cint);cdecl; external DLLSSLName;
function  SSL_CTX_get_security_level(ctx:PSSL_CTX):cint;cdecl; external DLLSSLName;
procedure SSL_CTX_set_security_callback(ctx:PSSL_CTX; cb:TSSL_security_cb);cdecl; external DLLSSLName;
function  SSL_CTX_get_security_callback(ctx:PSSL_CTX):TSSL_security_cb;cdecl; external DLLSSLName;
procedure SSL_CTX_set0_security_ex_data(ctx:PSSL_CTX; ex:pointer);cdecl; external DLLSSLName;
function  SSL_CTX_get0_security_ex_data(ctx:PSSL_CTX):pointer;cdecl; external DLLSSLName;

    const
      OPENSSL_INIT_NO_LOAD_SSL_STRINGS = $00100000;      
      OPENSSL_INIT_LOAD_SSL_STRINGS = $00200000;      
      OPENSSL_INIT_SSL_DEFAULT = OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS;      

function  OPENSSL_init_ssl(opts:uint64; settings:POPENSSL_INIT_SETTINGS):cint;cdecl; external DLLSSLName;
function  SSL_test_functions:Popenssl_ssl_test_functions;cdecl; external DLLUtilName;

function  ERR_load_SSL_strings:cint;cdecl; external DLLSSLName;

    const
      SSL_F_CHECK_SUITEB_CIPHER_LIST = 331;      
      SSL_F_CT_MOVE_SCTS = 345;      
      SSL_F_CT_STRICT = 349;      
      SSL_F_D2I_SSL_SESSION = 103;      
      SSL_F_DANE_CTX_ENABLE = 347;      
      SSL_F_DANE_MTYPE_SET = 393;      
      SSL_F_DANE_TLSA_ADD = 394;      
      SSL_F_DO_DTLS1_WRITE = 245;      
      SSL_F_DO_SSL3_WRITE = 104;      
      SSL_F_DTLS1_BUFFER_RECORD = 247;      
      SSL_F_DTLS1_CHECK_TIMEOUT_NUM = 318;      
      SSL_F_DTLS1_HEARTBEAT = 305;      
      SSL_F_DTLS1_PREPROCESS_FRAGMENT = 288;      
      SSL_F_DTLS1_PROCESS_BUFFERED_RECORDS = 424;      
      SSL_F_DTLS1_PROCESS_RECORD = 257;      
      SSL_F_DTLS1_READ_BYTES = 258;      
      SSL_F_DTLS1_READ_FAILED = 339;      
      SSL_F_DTLS1_RETRANSMIT_MESSAGE = 390;      
      SSL_F_DTLS1_WRITE_APP_DATA_BYTES = 268;      
      SSL_F_DTLSV1_LISTEN = 350;      
      SSL_F_DTLS_CONSTRUCT_CHANGE_CIPHER_SPEC = 371;      
      SSL_F_DTLS_CONSTRUCT_HELLO_VERIFY_REQUEST = 385;      
      SSL_F_DTLS_GET_REASSEMBLED_MESSAGE = 370;      
      SSL_F_DTLS_PROCESS_HELLO_VERIFY = 386;      
      SSL_F_OPENSSL_INIT_SSL = 342;      
      SSL_F_OSSL_STATEM_CLIENT_READ_TRANSITION = 417;      
      SSL_F_OSSL_STATEM_SERVER_READ_TRANSITION = 418;      
      SSL_F_READ_STATE_MACHINE = 352;      
      SSL_F_SSL3_CHANGE_CIPHER_STATE = 129;      
      SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM = 130;      
      SSL_F_SSL3_CTRL = 213;      
      SSL_F_SSL3_CTX_CTRL = 133;      
      SSL_F_SSL3_DIGEST_CACHED_RECORDS = 293;      
      SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC = 292;      
      SSL_F_SSL3_FINAL_FINISH_MAC = 285;      
      SSL_F_SSL3_GENERATE_KEY_BLOCK = 238;      
      SSL_F_SSL3_GENERATE_MASTER_SECRET = 388;      
      SSL_F_SSL3_GET_RECORD = 143;      
      SSL_F_SSL3_INIT_FINISHED_MAC = 397;      
      SSL_F_SSL3_OUTPUT_CERT_CHAIN = 147;      
      SSL_F_SSL3_READ_BYTES = 148;      
      SSL_F_SSL3_READ_N = 149;      
      SSL_F_SSL3_SETUP_KEY_BLOCK = 157;      
      SSL_F_SSL3_SETUP_READ_BUFFER = 156;      
      SSL_F_SSL3_SETUP_WRITE_BUFFER = 291;      
      SSL_F_SSL3_WRITE_BYTES = 158;      
      SSL_F_SSL3_WRITE_PENDING = 159;      
      SSL_F_SSL_ADD_CERT_CHAIN = 316;      
      SSL_F_SSL_ADD_CERT_TO_BUF = 319;      
      SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT = 298;      
      SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT = 277;      
      SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT = 307;      
      SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK = 215;      
      SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK = 216;      
      SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT = 299;      
      SSL_F_SSL_ADD_SERVERHELLO_TLSEXT = 278;      
      SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT = 308;      
      SSL_F_SSL_BAD_METHOD = 160;      
      SSL_F_SSL_BUILD_CERT_CHAIN = 332;      
      SSL_F_SSL_BYTES_TO_CIPHER_LIST = 161;      
      SSL_F_SSL_CERT_ADD0_CHAIN_CERT = 346;      
      SSL_F_SSL_CERT_DUP = 221;      
      SSL_F_SSL_CERT_NEW = 162;      
      SSL_F_SSL_CERT_SET0_CHAIN = 340;      
      SSL_F_SSL_CHECK_PRIVATE_KEY = 163;      
      SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT = 280;      
      SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG = 279;      
      SSL_F_SSL_CIPHER_PROCESS_RULESTR = 230;      
      SSL_F_SSL_CIPHER_STRENGTH_SORT = 231;      
      SSL_F_SSL_CLEAR = 164;      
      SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD = 165;      
      SSL_F_SSL_CONF_CMD = 334;      
      SSL_F_SSL_CREATE_CIPHER_LIST = 166;      
      SSL_F_SSL_CTRL = 232;      
      SSL_F_SSL_CTX_CHECK_PRIVATE_KEY = 168;      
      SSL_F_SSL_CTX_ENABLE_CT = 398;      
      SSL_F_SSL_CTX_MAKE_PROFILES = 309;      
      SSL_F_SSL_CTX_NEW = 169;      
      SSL_F_SSL_CTX_SET_ALPN_PROTOS = 343;      
      SSL_F_SSL_CTX_SET_CIPHER_LIST = 269;      
      SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE = 290;      
      SSL_F_SSL_CTX_SET_CT_VALIDATION_CALLBACK = 396;      
      SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT = 219;      
      SSL_F_SSL_CTX_SET_SSL_VERSION = 170;      
      SSL_F_SSL_CTX_USE_CERTIFICATE = 171;      
      SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1 = 172;      
      SSL_F_SSL_CTX_USE_CERTIFICATE_FILE = 173;      
      SSL_F_SSL_CTX_USE_PRIVATEKEY = 174;      
      SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1 = 175;      
      SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE = 176;      
      SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT = 272;      
      SSL_F_SSL_CTX_USE_RSAPRIVATEKEY = 177;      
      SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1 = 178;      
      SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE = 179;      
      SSL_F_SSL_CTX_USE_SERVERINFO = 336;      
      SSL_F_SSL_CTX_USE_SERVERINFO_FILE = 337;      
      SSL_F_SSL_DANE_DUP = 403;      
      SSL_F_SSL_DANE_ENABLE = 395;      
      SSL_F_SSL_DO_CONFIG = 391;      
      SSL_F_SSL_DO_HANDSHAKE = 180;      
      SSL_F_SSL_DUP_CA_LIST = 408;      
      SSL_F_SSL_ENABLE_CT = 402;      
      SSL_F_SSL_GET_NEW_SESSION = 181;      
      SSL_F_SSL_GET_PREV_SESSION = 217;      
      SSL_F_SSL_GET_SERVER_CERT_INDEX = 322;      
      SSL_F_SSL_GET_SIGN_PKEY = 183;      
      SSL_F_SSL_INIT_WBIO_BUFFER = 184;      
      SSL_F_SSL_LOAD_CLIENT_CA_FILE = 185;      
      SSL_F_SSL_MODULE_INIT = 392;      
      SSL_F_SSL_NEW = 186;      
      SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT = 300;      
      SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT = 302;      
      SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT = 310;      
      SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT = 301;      
      SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT = 303;      
      SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT = 311;      
      SSL_F_SSL_PEEK = 270;      
      SSL_F_SSL_READ = 223;      
      SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT = 320;      
      SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT = 321;      
      SSL_F_SSL_SESSION_DUP = 348;      
      SSL_F_SSL_SESSION_NEW = 189;      
      SSL_F_SSL_SESSION_PRINT_FP = 190;      
      SSL_F_SSL_SESSION_SET1_ID = 423;      
      SSL_F_SSL_SESSION_SET1_ID_CONTEXT = 312;      
      SSL_F_SSL_SET_ALPN_PROTOS = 344;      
      SSL_F_SSL_SET_CERT = 191;      
      SSL_F_SSL_SET_CIPHER_LIST = 271;      
      SSL_F_SSL_SET_CT_VALIDATION_CALLBACK = 399;      
      SSL_F_SSL_SET_FD = 192;      
      SSL_F_SSL_SET_PKEY = 193;      
      SSL_F_SSL_SET_RFD = 194;      
      SSL_F_SSL_SET_SESSION = 195;      
      SSL_F_SSL_SET_SESSION_ID_CONTEXT = 218;      
      SSL_F_SSL_SET_SESSION_TICKET_EXT = 294;      
      SSL_F_SSL_SET_WFD = 196;      
      SSL_F_SSL_SHUTDOWN = 224;      
      SSL_F_SSL_SRP_CTX_INIT = 313;      
      SSL_F_SSL_START_ASYNC_JOB = 389;      
      SSL_F_SSL_UNDEFINED_FUNCTION = 197;      
      SSL_F_SSL_UNDEFINED_VOID_FUNCTION = 244;      
      SSL_F_SSL_USE_CERTIFICATE = 198;      
      SSL_F_SSL_USE_CERTIFICATE_ASN1 = 199;      
      SSL_F_SSL_USE_CERTIFICATE_FILE = 200;      
      SSL_F_SSL_USE_PRIVATEKEY = 201;      
      SSL_F_SSL_USE_PRIVATEKEY_ASN1 = 202;      
      SSL_F_SSL_USE_PRIVATEKEY_FILE = 203;      
      SSL_F_SSL_USE_PSK_IDENTITY_HINT = 273;      
      SSL_F_SSL_USE_RSAPRIVATEKEY = 204;      
      SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1 = 205;      
      SSL_F_SSL_USE_RSAPRIVATEKEY_FILE = 206;      
      SSL_F_SSL_VALIDATE_CT = 400;      
      SSL_F_SSL_VERIFY_CERT_CHAIN = 207;      
      SSL_F_SSL_WRITE = 208;      
      SSL_F_STATE_MACHINE = 353;      
      SSL_F_TLS12_CHECK_PEER_SIGALG = 333;      
      SSL_F_TLS1_CHANGE_CIPHER_STATE = 209;      
      SSL_F_TLS1_CHECK_DUPLICATE_EXTENSIONS = 341;      
      SSL_F_TLS1_ENC = 401;      
      SSL_F_TLS1_EXPORT_KEYING_MATERIAL = 314;      
      SSL_F_TLS1_GET_CURVELIST = 338;      
      SSL_F_TLS1_PRF = 284;      
      SSL_F_TLS1_SETUP_KEY_BLOCK = 211;      
      SSL_F_TLS1_SET_SERVER_SIGALGS = 335;      
      SSL_F_TLS_CLIENT_KEY_EXCHANGE_POST_WORK = 354;      
      SSL_F_TLS_CONSTRUCT_CERTIFICATE_REQUEST = 372;      
      SSL_F_TLS_CONSTRUCT_CKE_DHE = 404;      
      SSL_F_TLS_CONSTRUCT_CKE_ECDHE = 405;      
      SSL_F_TLS_CONSTRUCT_CKE_GOST = 406;      
      SSL_F_TLS_CONSTRUCT_CKE_PSK_PREAMBLE = 407;      
      SSL_F_TLS_CONSTRUCT_CKE_RSA = 409;      
      SSL_F_TLS_CONSTRUCT_CKE_SRP = 410;      
      SSL_F_TLS_CONSTRUCT_CLIENT_CERTIFICATE = 355;      
      SSL_F_TLS_CONSTRUCT_CLIENT_HELLO = 356;      
      SSL_F_TLS_CONSTRUCT_CLIENT_KEY_EXCHANGE = 357;      
      SSL_F_TLS_CONSTRUCT_CLIENT_VERIFY = 358;      
      SSL_F_TLS_CONSTRUCT_FINISHED = 359;      
      SSL_F_TLS_CONSTRUCT_HELLO_REQUEST = 373;      
      SSL_F_TLS_CONSTRUCT_NEW_SESSION_TICKET = 428;      
      SSL_F_TLS_CONSTRUCT_SERVER_CERTIFICATE = 374;      
      SSL_F_TLS_CONSTRUCT_SERVER_DONE = 375;      
      SSL_F_TLS_CONSTRUCT_SERVER_HELLO = 376;      
      SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE = 377;      
      SSL_F_TLS_GET_MESSAGE_BODY = 351;      
      SSL_F_TLS_GET_MESSAGE_HEADER = 387;      
      SSL_F_TLS_POST_PROCESS_CLIENT_HELLO = 378;      
      SSL_F_TLS_POST_PROCESS_CLIENT_KEY_EXCHANGE = 384;      
      SSL_F_TLS_PREPARE_CLIENT_CERTIFICATE = 360;      
      SSL_F_TLS_PROCESS_CERTIFICATE_REQUEST = 361;      
      SSL_F_TLS_PROCESS_CERT_STATUS = 362;      
      SSL_F_TLS_PROCESS_CERT_VERIFY = 379;      
      SSL_F_TLS_PROCESS_CHANGE_CIPHER_SPEC = 363;      
      SSL_F_TLS_PROCESS_CKE_DHE = 411;      
      SSL_F_TLS_PROCESS_CKE_ECDHE = 412;      
      SSL_F_TLS_PROCESS_CKE_GOST = 413;      
      SSL_F_TLS_PROCESS_CKE_PSK_PREAMBLE = 414;      
      SSL_F_TLS_PROCESS_CKE_RSA = 415;      
      SSL_F_TLS_PROCESS_CKE_SRP = 416;      
      SSL_F_TLS_PROCESS_CLIENT_CERTIFICATE = 380;      
      SSL_F_TLS_PROCESS_CLIENT_HELLO = 381;      
      SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE = 382;      
      SSL_F_TLS_PROCESS_FINISHED = 364;      
      SSL_F_TLS_PROCESS_KEY_EXCHANGE = 365;      
      SSL_F_TLS_PROCESS_NEW_SESSION_TICKET = 366;      
      SSL_F_TLS_PROCESS_NEXT_PROTO = 383;      
      SSL_F_TLS_PROCESS_SERVER_CERTIFICATE = 367;      
      SSL_F_TLS_PROCESS_SERVER_DONE = 368;      
      SSL_F_TLS_PROCESS_SERVER_HELLO = 369;      
      SSL_F_TLS_PROCESS_SKE_DHE = 419;      
      SSL_F_TLS_PROCESS_SKE_ECDHE = 420;      
      SSL_F_TLS_PROCESS_SKE_PSK_PREAMBLE = 421;      
      SSL_F_TLS_PROCESS_SKE_SRP = 422;      
      SSL_F_USE_CERTIFICATE_CHAIN_FILE = 220;      
      SSL_R_APP_DATA_IN_HANDSHAKE = 100;      
      SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT = 272;      
      SSL_R_AT_LEAST_TLS_1_0_NEEDED_IN_FIPS_MODE = 143;      
      SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE = 158;      
      SSL_R_BAD_CHANGE_CIPHER_SPEC = 103;      
      SSL_R_BAD_DATA = 390;      
      SSL_R_BAD_DATA_RETURNED_BY_CALLBACK = 106;      
      SSL_R_BAD_DECOMPRESSION = 107;      
      SSL_R_BAD_DH_VALUE = 102;      
      SSL_R_BAD_DIGEST_LENGTH = 111;      
      SSL_R_BAD_ECC_CERT = 304;      
      SSL_R_BAD_ECPOINT = 306;      
      SSL_R_BAD_HANDSHAKE_LENGTH = 332;      
      SSL_R_BAD_HELLO_REQUEST = 105;      
      SSL_R_BAD_LENGTH = 271;      
      SSL_R_BAD_PACKET_LENGTH = 115;      
      SSL_R_BAD_PROTOCOL_VERSION_NUMBER = 116;      
      SSL_R_BAD_RSA_ENCRYPT = 119;      
      SSL_R_BAD_SIGNATURE = 123;      
      SSL_R_BAD_SRP_A_LENGTH = 347;      
      SSL_R_BAD_SRP_PARAMETERS = 371;      
      SSL_R_BAD_SRTP_MKI_VALUE = 352;      
      SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST = 353;      
      SSL_R_BAD_SSL_FILETYPE = 124;      
      SSL_R_BAD_VALUE = 384;      
      SSL_R_BAD_WRITE_RETRY = 127;      
      SSL_R_BIO_NOT_SET = 128;      
      SSL_R_BLOCK_CIPHER_PAD_IS_WRONG = 129;      
      SSL_R_BN_LIB = 130;      
      SSL_R_CA_DN_LENGTH_MISMATCH = 131;      
      SSL_R_CA_KEY_TOO_SMALL = 397;      
      SSL_R_CA_MD_TOO_WEAK = 398;      
      SSL_R_CCS_RECEIVED_EARLY = 133;      
      SSL_R_CERTIFICATE_VERIFY_FAILED = 134;      
      SSL_R_CERT_CB_ERROR = 377;      
      SSL_R_CERT_LENGTH_MISMATCH = 135;      
      SSL_R_CIPHER_CODE_WRONG_LENGTH = 137;      
      SSL_R_CIPHER_OR_HASH_UNAVAILABLE = 138;      
      SSL_R_CLIENTHELLO_TLSEXT = 226;      
      SSL_R_COMPRESSED_LENGTH_TOO_LONG = 140;      
      SSL_R_COMPRESSION_DISABLED = 343;      
      SSL_R_COMPRESSION_FAILURE = 141;      
      SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE = 307;      
      SSL_R_COMPRESSION_LIBRARY_ERROR = 142;      
      SSL_R_CONNECTION_TYPE_NOT_SET = 144;      
      SSL_R_CONTEXT_NOT_DANE_ENABLED = 167;      
      SSL_R_COOKIE_GEN_CALLBACK_FAILURE = 400;      
      SSL_R_COOKIE_MISMATCH = 308;      
      SSL_R_CUSTOM_EXT_HANDLER_ALREADY_INSTALLED = 206;      
      SSL_R_DANE_ALREADY_ENABLED = 172;      
      SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL = 173;      
      SSL_R_DANE_NOT_ENABLED = 175;      
      SSL_R_DANE_TLSA_BAD_CERTIFICATE = 180;      
      SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE = 184;      
      SSL_R_DANE_TLSA_BAD_DATA_LENGTH = 189;      
      SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH = 192;      
      SSL_R_DANE_TLSA_BAD_MATCHING_TYPE = 200;      
      SSL_R_DANE_TLSA_BAD_PUBLIC_KEY = 201;      
      SSL_R_DANE_TLSA_BAD_SELECTOR = 202;      
      SSL_R_DANE_TLSA_NULL_DATA = 203;      
      SSL_R_DATA_BETWEEN_CCS_AND_FINISHED = 145;      
      SSL_R_DATA_LENGTH_TOO_LONG = 146;      
      SSL_R_DECRYPTION_FAILED = 147;      
      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC = 281;      
      SSL_R_DH_KEY_TOO_SMALL = 394;      
      SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG = 148;      
      SSL_R_DIGEST_CHECK_FAILED = 149;      
      SSL_R_DTLS_MESSAGE_TOO_BIG = 334;      
      SSL_R_DUPLICATE_COMPRESSION_ID = 309;      
      SSL_R_ECC_CERT_NOT_FOR_SIGNING = 318;      
      SSL_R_ECDH_REQUIRED_FOR_SUITEB_MODE = 374;      
      SSL_R_EE_KEY_TOO_SMALL = 399;      
      SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST = 354;      
      SSL_R_ENCRYPTED_LENGTH_TOO_LONG = 150;      
      SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST = 151;      
      SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN = 204;      
      SSL_R_EXCEEDS_MAX_FRAGMENT_SIZE = 194;      
      SSL_R_EXCESSIVE_MESSAGE_SIZE = 152;      
      SSL_R_EXTRA_DATA_IN_MESSAGE = 153;      
      SSL_R_FAILED_TO_INIT_ASYNC = 405;      
      SSL_R_FRAGMENTED_CLIENT_HELLO = 401;      
      SSL_R_GOT_A_FIN_BEFORE_A_CCS = 154;      
      SSL_R_HTTPS_PROXY_REQUEST = 155;      
      SSL_R_HTTP_REQUEST = 156;      
      SSL_R_ILLEGAL_SUITEB_DIGEST = 380;      
      SSL_R_INAPPROPRIATE_FALLBACK = 373;      
      SSL_R_INCONSISTENT_COMPRESSION = 340;      
      SSL_R_INCONSISTENT_EXTMS = 104;      
      SSL_R_INVALID_COMMAND = 280;      
      SSL_R_INVALID_COMPRESSION_ALGORITHM = 341;      
      SSL_R_INVALID_CONFIGURATION_NAME = 113;      
      SSL_R_INVALID_CT_VALIDATION_TYPE = 212;      
      SSL_R_INVALID_NULL_CMD_NAME = 385;      
      SSL_R_INVALID_SEQUENCE_NUMBER = 402;      
      SSL_R_INVALID_SERVERINFO_DATA = 388;      
      SSL_R_INVALID_SRP_USERNAME = 357;      
      SSL_R_INVALID_STATUS_RESPONSE = 328;      
      SSL_R_INVALID_TICKET_KEYS_LENGTH = 325;      
      SSL_R_LENGTH_MISMATCH = 159;      
      SSL_R_LENGTH_TOO_LONG = 404;      
      SSL_R_LENGTH_TOO_SHORT = 160;      
      SSL_R_LIBRARY_BUG = 274;      
      SSL_R_LIBRARY_HAS_NO_CIPHERS = 161;      
      SSL_R_MISSING_DSA_SIGNING_CERT = 165;      
      SSL_R_MISSING_ECDSA_SIGNING_CERT = 381;      
      SSL_R_MISSING_RSA_CERTIFICATE = 168;      
      SSL_R_MISSING_RSA_ENCRYPTING_CERT = 169;      
      SSL_R_MISSING_RSA_SIGNING_CERT = 170;      
      SSL_R_MISSING_SRP_PARAM = 358;      
      SSL_R_MISSING_TMP_DH_KEY = 171;      
      SSL_R_MISSING_TMP_ECDH_KEY = 311;      
      SSL_R_NO_CERTIFICATES_RETURNED = 176;      
      SSL_R_NO_CERTIFICATE_ASSIGNED = 177;      
      SSL_R_NO_CERTIFICATE_SET = 179;      
      SSL_R_NO_CIPHERS_AVAILABLE = 181;      
      SSL_R_NO_CIPHERS_SPECIFIED = 183;      
      SSL_R_NO_CIPHER_MATCH = 185;      
      SSL_R_NO_CLIENT_CERT_METHOD = 331;      
      SSL_R_NO_COMPRESSION_SPECIFIED = 187;      
      SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER = 330;      
      SSL_R_NO_METHOD_SPECIFIED = 188;      
      SSL_R_NO_PEM_EXTENSIONS = 389;      
      SSL_R_NO_PRIVATE_KEY_ASSIGNED = 190;      
      SSL_R_NO_PROTOCOLS_AVAILABLE = 191;      
      SSL_R_NO_RENEGOTIATION = 339;      
      SSL_R_NO_REQUIRED_DIGEST = 324;      
      SSL_R_NO_SHARED_CIPHER = 193;      
      SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS = 376;      
      SSL_R_NO_SRTP_PROFILES = 359;      
      SSL_R_NO_VALID_SCTS = 216;      
      SSL_R_NO_VERIFY_COOKIE_CALLBACK = 403;      
      SSL_R_NULL_SSL_CTX = 195;      
      SSL_R_NULL_SSL_METHOD_PASSED = 196;      
      SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED = 197;      
      SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED = 344;      
      SSL_R_PACKET_LENGTH_TOO_LONG = 198;      
      SSL_R_PARSE_TLSEXT = 227;      
      SSL_R_PATH_TOO_LONG = 270;      
      SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE = 199;      
      SSL_R_PEM_NAME_BAD_PREFIX = 391;      
      SSL_R_PEM_NAME_TOO_SHORT = 392;      
      SSL_R_PIPELINE_FAILURE = 406;      
      SSL_R_PROTOCOL_IS_SHUTDOWN = 207;      
      SSL_R_PSK_IDENTITY_NOT_FOUND = 223;      
      SSL_R_PSK_NO_CLIENT_CB = 224;      
      SSL_R_PSK_NO_SERVER_CB = 225;      
      SSL_R_READ_BIO_NOT_SET = 211;      
      SSL_R_READ_TIMEOUT_EXPIRED = 312;      
      SSL_R_RECORD_LENGTH_MISMATCH = 213;      
      SSL_R_RECORD_TOO_SMALL = 298;      
      SSL_R_RENEGOTIATE_EXT_TOO_LONG = 335;      
      SSL_R_RENEGOTIATION_ENCODING_ERR = 336;      
      SSL_R_RENEGOTIATION_MISMATCH = 337;      
      SSL_R_REQUIRED_CIPHER_MISSING = 215;      
      SSL_R_REQUIRED_COMPRESSION_ALGORITHM_MISSING = 342;      
      SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING = 345;      
      SSL_R_SCT_VERIFICATION_FAILED = 208;      
      SSL_R_SERVERHELLO_TLSEXT = 275;      
      SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED = 277;      
      SSL_R_SHUTDOWN_WHILE_IN_INIT = 407;      
      SSL_R_SIGNATURE_ALGORITHMS_ERROR = 360;      
      SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE = 220;      
      SSL_R_SRP_A_CALC = 361;      
      SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES = 362;      
      SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG = 363;      
      SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE = 364;      
      SSL_R_SSL3_EXT_INVALID_SERVERNAME = 319;      
      SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE = 320;      
      SSL_R_SSL3_SESSION_ID_TOO_LONG = 300;      
      SSL_R_SSLV3_ALERT_BAD_CERTIFICATE = 1042;      
      SSL_R_SSLV3_ALERT_BAD_RECORD_MAC = 1020;      
      SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED = 1045;      
      SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED = 1044;      
      SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 1046;      
      SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE = 1030;      
      SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE = 1040;      
      SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER = 1047;      
      SSL_R_SSLV3_ALERT_NO_CERTIFICATE = 1041;      
      SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE = 1010;      
      SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE = 1043;      
      SSL_R_SSL_COMMAND_SECTION_EMPTY = 117;      
      SSL_R_SSL_COMMAND_SECTION_NOT_FOUND = 125;      
      SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION = 228;      
      SSL_R_SSL_HANDSHAKE_FAILURE = 229;      
      SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS = 230;      
      SSL_R_SSL_NEGATIVE_LENGTH = 372;      
      SSL_R_SSL_SECTION_EMPTY = 126;      
      SSL_R_SSL_SECTION_NOT_FOUND = 136;      
      SSL_R_SSL_SESSION_ID_CALLBACK_FAILED = 301;      
      SSL_R_SSL_SESSION_ID_CONFLICT = 302;      
      SSL_R_SSL_SESSION_ID_TOO_LONG = 408;      
      SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG = 273;      
      SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH = 303;      
      SSL_R_SSL_SESSION_VERSION_MISMATCH = 210;      
      SSL_R_TLSV1_ALERT_ACCESS_DENIED = 1049;      
      SSL_R_TLSV1_ALERT_DECODE_ERROR = 1050;      
      SSL_R_TLSV1_ALERT_DECRYPTION_FAILED = 1021;      
      SSL_R_TLSV1_ALERT_DECRYPT_ERROR = 1051;      
      SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION = 1060;      
      SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK = 1086;      
      SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY = 1071;      
      SSL_R_TLSV1_ALERT_INTERNAL_ERROR = 1080;      
      SSL_R_TLSV1_ALERT_NO_RENEGOTIATION = 1100;      
      SSL_R_TLSV1_ALERT_PROTOCOL_VERSION = 1070;      
      SSL_R_TLSV1_ALERT_RECORD_OVERFLOW = 1022;      
      SSL_R_TLSV1_ALERT_UNKNOWN_CA = 1048;      
      SSL_R_TLSV1_ALERT_USER_CANCELLED = 1090;      
      SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE = 1114;      
      SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE = 1113;      
      SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE = 1111;      
      SSL_R_TLSV1_UNRECOGNIZED_NAME = 1112;      
      SSL_R_TLSV1_UNSUPPORTED_EXTENSION = 1110;      
      SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT = 365;      
      SSL_R_TLS_HEARTBEAT_PENDING = 366;      
      SSL_R_TLS_ILLEGAL_EXPORTER_LABEL = 367;      
      SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST = 157;      
      SSL_R_TOO_MANY_WARN_ALERTS = 409;      
      SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS = 314;      
      SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS = 239;      
      SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES = 242;      
      SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES = 243;      
      SSL_R_UNEXPECTED_MESSAGE = 244;      
      SSL_R_UNEXPECTED_RECORD = 245;      
      SSL_R_UNINITIALIZED = 276;      
      SSL_R_UNKNOWN_ALERT_TYPE = 246;      
      SSL_R_UNKNOWN_CERTIFICATE_TYPE = 247;      
      SSL_R_UNKNOWN_CIPHER_RETURNED = 248;      
      SSL_R_UNKNOWN_CIPHER_TYPE = 249;      
      SSL_R_UNKNOWN_CMD_NAME = 386;      
      SSL_R_UNKNOWN_COMMAND = 139;      
      SSL_R_UNKNOWN_DIGEST = 368;      
      SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE = 250;      
      SSL_R_UNKNOWN_PKEY_TYPE = 251;      
      SSL_R_UNKNOWN_PROTOCOL = 252;      
      SSL_R_UNKNOWN_SSL_VERSION = 254;      
      SSL_R_UNKNOWN_STATE = 255;      
      SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED = 338;      
      SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM = 257;      
      SSL_R_UNSUPPORTED_ELLIPTIC_CURVE = 315;      
      SSL_R_UNSUPPORTED_PROTOCOL = 258;      
      SSL_R_UNSUPPORTED_SSL_VERSION = 259;      
      SSL_R_UNSUPPORTED_STATUS_TYPE = 329;      
      SSL_R_USE_SRTP_NOT_NEGOTIATED = 369;      
      SSL_R_VERSION_TOO_HIGH = 166;      
      SSL_R_VERSION_TOO_LOW = 396;      
      SSL_R_WRONG_CERTIFICATE_TYPE = 383;      
      SSL_R_WRONG_CIPHER_RETURNED = 261;      
      SSL_R_WRONG_CURVE = 378;      
      SSL_R_WRONG_SIGNATURE_LENGTH = 264;      
      SSL_R_WRONG_SIGNATURE_SIZE = 265;      
      SSL_R_WRONG_SIGNATURE_TYPE = 370;      
      SSL_R_WRONG_SSL_VERSION = 266;      
      SSL_R_WRONG_VERSION_NUMBER = 267;      
      SSL_R_X509_LIB = 268;      
      SSL_R_X509_VERIFICATION_SETUP_PROBLEMS = 269;      
{$define HEADER_ERR_H}    

    function  ERR_PUT_error(a,b,c,d,e : longint) : longint; cdecl; external DLLUtilName;

    const
      ERR_TXT_MALLOCED = $01;      
      ERR_TXT_STRING = $02;      
      ERR_FLAG_MARK = $01;      
      ERR_NUM_ERRORS = 16;

    type
      Perr_state= ^Terr_state_st;
      Terr_state_st = record
          err_flags : array[0..15] of cint;
          err_buffer : array[0..15] of culong;
          err_data : array[0..15] of pbyte;
          err_data_flags : array[0..15] of cint;
          err_file : array[0..15] of pbyte;
          err_line : array[0..15] of cint;
          top : cint;
          bottom : cint;
        end;

    const
      ERR_LIB_NONE = 1;      
      ERR_LIB_SYS = 2;      
      ERR_LIB_BN = 3;      
      ERR_LIB_RSA = 4;      
      ERR_LIB_DH = 5;      
      ERR_LIB_EVP = 6;      
      ERR_LIB_BUF = 7;      
      ERR_LIB_OBJ = 8;      
      ERR_LIB_PEM = 9;      
      ERR_LIB_DSA = 10;      
      ERR_LIB_X509 = 11;      
      ERR_LIB_ASN1 = 13;      
      ERR_LIB_CONF = 14;      
      ERR_LIB_CRYPTO = 15;      
      ERR_LIB_EC = 16;      
      ERR_LIB_SSL = 20;      
      ERR_LIB_BIO = 32;      
      ERR_LIB_PKCS7 = 33;      
      ERR_LIB_X509V3 = 34;      
      ERR_LIB_PKCS12 = 35;      
      ERR_LIB_RAND = 36;      
      ERR_LIB_DSO = 37;      
      ERR_LIB_ENGINE = 38;      
      ERR_LIB_OCSP = 39;      
      ERR_LIB_UI = 40;      
      ERR_LIB_COMP = 41;      
      ERR_LIB_ECDSA = 42;      
      ERR_LIB_ECDH = 43;      
      ERR_LIB_STORE = 44;      
      ERR_LIB_FIPS = 45;      
      ERR_LIB_CMS = 46;      
      ERR_LIB_TS = 47;      
      ERR_LIB_HMAC = 48;      
      ERR_LIB_CT = 50;      
      ERR_LIB_ASYNC = 51;      
      ERR_LIB_KDF = 52;      
      ERR_LIB_USER = 128;      

    Procedure  SYSerr(f,r : cint);

    Procedure  BNerr(f,r : cint);

    Procedure  RSAerr(f,r : cint);

    Procedure  DHerr(f,r : cint);

    Procedure  EVPerr(f,r : cint);

    Procedure  BUFerr(f,r : cint);

    Procedure  OBJerr(f,r : cint);

    Procedure  PEMerr(f,r : cint);

    Procedure  DSAerr(f,r : cint);

    Procedure  X509err(f,r : cint);

    Procedure  ASN1err(f,r : cint);

    Procedure  CONFerr(f,r : cint);

    Procedure  CRYPTOerr(f,r : cint);

    Procedure  ECerr(f,r : cint);

    Procedure  SSLerr(f,r : cint);

    Procedure  BIOerr(f,r : cint);

    Procedure  PKCS7err(f,r : cint);

    Procedure  X509V3err(f,r : cint);

    Procedure  PKCS12err(f,r : cint);

    Procedure  RANDerr(f,r : cint);

    Procedure  DSOerr(f,r : cint);

    Procedure  ENGINEerr(f,r : cint);

    Procedure  OCSPerr(f,r : cint);

    Procedure  UIerr(f,r : cint);

    Procedure  COMPerr(f,r : cint);

    Procedure  ECDSAerr(f,r : cint);

    Procedure  ECDHerr(f,r : cint);

    Procedure  STOREerr(f,r : cint);

    Procedure  FIPSerr(f,r : cint);

    Procedure  CMSerr(f,r : cint);

    Procedure  TSerr(f,r : cint);

    Procedure  HMACerr(f,r : cint);

    Procedure  CTerr(f,r : cint);

    Procedure  ASYNCerr(f,r : cint);

    Procedure  KDFerr(f,r : cint);

    function  ERR_GET_LIB(l : longint) : cint;

    function  ERR_GET_FUNC(l : cint) : cint;

    const
      SYS_F_FOPEN = 1;      
      SYS_F_CONNECT = 2;      
      SYS_F_GETSERVBYNAME = 3;      
      SYS_F_SOCKET = 4;      
      SYS_F_IOCTLSOCKET = 5;      
      SYS_F_BIND = 6;      
      SYS_F_LISTEN = 7;      
      SYS_F_ACCEPT = 8;      
      SYS_F_WSASTARTUP = 9;      
      SYS_F_OPENDIR = 10;      
      SYS_F_FREAD = 11;      
      SYS_F_GETADDRINFO = 12;      
      SYS_F_GETNAMEINFO = 13;      
      SYS_F_SETSOCKOPT = 14;      
      SYS_F_GETSOCKOPT = 15;      
      SYS_F_GETSOCKNAME = 16;      
      SYS_F_GETHOSTBYNAME = 17;      
      SYS_F_FFLUSH = 18;      
      ERR_R_SYS_LIB = ERR_LIB_SYS;      
      ERR_R_BN_LIB = ERR_LIB_BN;      
      ERR_R_RSA_LIB = ERR_LIB_RSA;      
      ERR_R_DH_LIB = ERR_LIB_DH;      
      ERR_R_EVP_LIB = ERR_LIB_EVP;      
      ERR_R_BUF_LIB = ERR_LIB_BUF;      
      ERR_R_OBJ_LIB = ERR_LIB_OBJ;      
      ERR_R_PEM_LIB = ERR_LIB_PEM;      
      ERR_R_DSA_LIB = ERR_LIB_DSA;      
      ERR_R_X509_LIB = ERR_LIB_X509;      
      ERR_R_ASN1_LIB = ERR_LIB_ASN1;      
      ERR_R_EC_LIB = ERR_LIB_EC;      
      ERR_R_BIO_LIB = ERR_LIB_BIO;      
      ERR_R_PKCS7_LIB = ERR_LIB_PKCS7;      
      ERR_R_X509V3_LIB = ERR_LIB_X509V3;      
      ERR_R_ENGINE_LIB = ERR_LIB_ENGINE;      
      ERR_R_ECDSA_LIB = ERR_LIB_ECDSA;      
      ERR_R_NESTED_ASN1_ERROR = 58;      
      ERR_R_MISSING_ASN1_EOS = 63;      
      ERR_R_FATAL = 64;      
      ERR_R_MALLOC_FAILURE = 1 or ERR_R_FATAL;      
      ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = 2 or ERR_R_FATAL;      
      ERR_R_PASSED_NULL_PARAMETER = 3 or ERR_R_FATAL;      
      ERR_R_INTERNAL_ERROR = 4 or ERR_R_FATAL;      
      ERR_R_DISABLED = 5 or ERR_R_FATAL;      
      ERR_R_INIT_FAIL = 6 or ERR_R_FATAL;      
      ERR_R_PASSED_INVALID_ARGUMENT = 7;

    type
      PERR_string_data= ^TERR_string_data_st;
      TERR_string_data_st = record
          error : culong;
          _string : pbyte;
        end;

      Plhash_st_ERR_STRING_DATA = ^Tlhash_st_ERR_STRING_DATA;
      Tlhash_st_ERR_STRING_DATA = record
          dummy : record
              case longint of
                0 : ( d1 : pointer );
                1 : ( d2 : culong );
                2 : ( d3 : cint );
              end;
        end;

      TERR_print_errors_cb=function  (str:pbyte; len:size_t; u:pointer):cint;cdecl;

procedure ERR_put_error(lib:cint; func:cint; reason:cint; _file:pbyte; line:cint);cdecl; external DLLUtilName;
procedure ERR_set_error_data(data:pbyte; flags:cint);cdecl; external DLLUtilName;
function  ERR_get_error:culong;cdecl; external DLLUtilName;
function  ERR_get_error_line(_file:Ppbyte; line:pcint):culong;cdecl; external DLLUtilName;
function  ERR_get_error_line_data(_file:Ppbyte; line:pcint; data:Ppbyte; flags:pcint):culong;cdecl; external DLLUtilName;
function  ERR_peek_error:culong;cdecl; external DLLUtilName;
function  ERR_peek_error_line(_file:Ppbyte; line:pcint):culong;cdecl; external DLLUtilName;
function  ERR_peek_error_line_data(_file:Ppbyte; line:pcint; data:Ppbyte; flags:pcint):culong;cdecl; external DLLUtilName;
function  ERR_peek_last_error:culong;cdecl; external DLLUtilName;
function  ERR_peek_last_error_line(_file:Ppbyte; line:pcint):culong;cdecl; external DLLUtilName;
function  ERR_peek_last_error_line_data(_file:Ppbyte; line:pcint; data:Ppbyte; flags:pcint):culong;cdecl; external DLLUtilName;
procedure ERR_clear_error;cdecl; external DLLUtilName;
function  ERR_error_string(e:culong; buf:pbyte):PChar;cdecl; external DLLUtilName;
procedure ERR_error_string_n(e:culong; buf:pbyte; len:size_t);cdecl; external DLLUtilName;
function  ERR_lib_error_string(e:culong):pbyte;cdecl; external DLLUtilName;
function  ERR_func_error_string(e:culong):pbyte;cdecl; external DLLUtilName;
function  ERR_reason_error_string(e:culong):pbyte;cdecl; external DLLUtilName;
procedure ERR_print_errors_cb(cb:TERR_print_errors_cb; u:pointer);cdecl; external DLLUtilName;
//procedure ERR_print_errors_fp(fp:PFILE);cdecl; external DLLUtilName;
procedure ERR_print_errors(bp:PBIO);cdecl; external DLLUtilName;
procedure ERR_add_error_data(num:cint; args:array of const);cdecl; external DLLUtilName;
//procedure ERR_add_error_vdata(num:cint; args:Tva_list);cdecl; external DLLUtilName;
function  ERR_load_strings(lib:cint; str:PERR_STRING_DATA):cint;cdecl; external DLLUtilName;
function  ERR_unload_strings(lib:cint; str:PERR_STRING_DATA):cint;cdecl; external DLLUtilName;
function  ERR_load_ERR_strings:cint;cdecl; external DLLUtilName;

function  ERR_get_next_error_library:cint;cdecl; external DLLUtilName;
function  ERR_set_mark:cint;cdecl; external DLLUtilName;
function  ERR_pop_to_mark:cint;cdecl; external DLLUtilName;

{$define HEADER_CONF_H}    
    type
      PPCONF_VALUE=^PCONF_VALUE;
      PCONF_VALUE = ^TCONF_VALUE;
      TCONF_VALUE = record
          section : pbyte;
          name : pbyte;
          value : pbyte;
        end;
      Pstack_st_CONF_VALUE = ^Tstack_st_CONF_VALUE;
      Tstack_st_CONF_VALUE = record
          {undefined structure}
        end;


      Tsk_CONF_VALUE_compfunc = function  (a:PPCONF_VALUE; b:PPCONF_VALUE):cint;cdecl;

      Tsk_CONF_VALUE_freefunc = procedure (a:PCONF_VALUE);cdecl;

      Tsk_CONF_VALUE_copyfunc = function  (a:PCONF_VALUE):PCONF_VALUE;cdecl;

    type
      Pconf_method= ^Tconf_method_st;
      Tconf_method_st = record
          name : pbyte;
          create : function  (meth:PCONF_METHOD):PCONF;cdecl;
          init : function  (conf:PCONF):cint;cdecl;
          destroy : function  (conf:PCONF):cint;cdecl;
          destroy_data : function  (conf:PCONF):cint;cdecl;
          load_bio : function  (conf:PCONF; bp:PBIO; eline:pclong):cint;cdecl;
          dump : function  (conf:PCONF; bp:PBIO):cint;cdecl;
          is_number : function  (conf:PCONF; c:byte):cint;cdecl;
          to_int : function  (conf:PCONF; c:byte):cint;cdecl;
          load : function  (conf:PCONF; name:pbyte; eline:pclong):cint;cdecl;
        end;

      PCONF_MODULE=^conf_module_st;
      PPCONF_MODULE=^PCONF_MODULE;

      PCONF_IMODULE=^conf_imodule_st;
      PPCONF_IMODULE=^PCONF_IMODULE;
      conf_imodule_st=record
       pmod:PCONF_MODULE;
       name:PChar;
       value:PChar;
       flags:cuint;
       usr_data:Pointer;
      end;

      // DSO module function typedefs
      Tconf_init_func=function(md:PCONF_IMODULE;cnf:PCONF):cint;cdecl;
      Tconf_finish_func=Procedure(md:PCONF_IMODULE);cdecl;

      conf_module_st=record
       // DSO of this module or NULL if static
       dso:Pointer;
       // Name of the module
       name:PChar;
       init:Tconf_init_func;
       finish:Tconf_finish_func;
       links:cint;
       usr_data:Pointer;
      end;

      Tsk_CONF_MODULE_compfunc = function  (a:PPCONF_MODULE; b:PPCONF_MODULE):cint;cdecl;

      Tsk_CONF_MODULE_freefunc = procedure (a:PCONF_MODULE);cdecl;

      Tsk_CONF_MODULE_copyfunc = function  (a:PCONF_MODULE):PCONF_MODULE;cdecl;

      Tsk_CONF_IMODULE_compfunc = function  (a:PPCONF_IMODULE; b:PPCONF_IMODULE):cint;cdecl;

      Tsk_CONF_IMODULE_freefunc = procedure (a:PCONF_IMODULE);cdecl;

      Tsk_CONF_IMODULE_copyfunc = function  (a:PCONF_IMODULE):PCONF_IMODULE;cdecl;

    const
      CONF_MFLAGS_IGNORE_ERRORS = $1;      
      CONF_MFLAGS_IGNORE_RETURN_CODES = $2;      
      CONF_MFLAGS_SILENT = $4;      
      CONF_MFLAGS_NO_DSO = $8;      
      CONF_MFLAGS_IGNORE_MISSING_FILE = $10;      
      CONF_MFLAGS_DEFAULT_SECTION = $20;      

type
 Plhash_st_CONF_VALUE=Pointer;

 TCONF_list_cb=function  (elem:pbyte; len:cint; usr:pointer):cint;cdecl;

function  CONF_set_default_method(meth:PCONF_METHOD):cint;cdecl; external DLLUtilName;
procedure CONF_set_nconf(conf:PCONF; hash:Plhash_st_CONF_VALUE);cdecl; external DLLUtilName;
function  CONF_get_string(conf:Plhash_st_CONF_VALUE; group:pbyte; name:pbyte):pbyte;cdecl; external DLLUtilName;
function  CONF_get_number(conf:Plhash_st_CONF_VALUE; group:pbyte; name:pbyte):clong;cdecl; external DLLUtilName;
procedure CONF_free(conf:Plhash_st_CONF_VALUE);cdecl; external DLLUtilName;
//function  CONF_dump_fp(conf:Plhash_st_CONF_VALUE;_out:PFILE):cint;cdecl; external DLLUtilName;
function  CONF_dump_bio(conf:Plhash_st_CONF_VALUE;_out:PBIO):cint;cdecl; external DLLUtilName;

function  NCONF_new(meth:PCONF_METHOD):PCONF;cdecl; external DLLUtilName;
function  NCONF_default:PCONF_METHOD;cdecl; external DLLUtilName;
function  NCONF_WIN32:PCONF_METHOD;cdecl; external DLLUtilName;
procedure NCONF_free(conf:PCONF);cdecl; external DLLUtilName;
procedure NCONF_free_data(conf:PCONF);cdecl; external DLLUtilName;
function  NCONF_load(conf:PCONF; _file:pbyte; eline:pclong):cint;cdecl; external DLLUtilName;
//function  NCONF_load_fp(conf:PCONF; fp:PFILE; eline:pclong):cint;cdecl; external DLLUtilName;
function  NCONF_load_bio(conf:PCONF; bp:PBIO; eline:pclong):cint;cdecl; external DLLUtilName;
function  NCONF_get_string(conf:PCONF; group:pbyte; name:pbyte):pbyte;cdecl; external DLLUtilName;
function  NCONF_get_number_e(conf:PCONF; group:pbyte; name:pbyte; result:pclong):cint;cdecl; external DLLUtilName;
//function  NCONF_dump_fp(conf:PCONF;_out:PFILE):cint;cdecl; external DLLUtilName;
function  NCONF_dump_bio(conf:PCONF;_out:PBIO):cint;cdecl; external DLLUtilName;

    function  NCONF_get_number(c:PCONF;g:pbyte;n:pbyte;r:pclong):cint;

function  CONF_modules_load(cnf:PCONF; appname:pbyte; flags:culong):cint;cdecl; external DLLUtilName;
function  CONF_modules_load_file(filename:pbyte; appname:pbyte; flags:culong):cint;cdecl; external DLLUtilName;
procedure CONF_modules_unload(all:cint);cdecl; external DLLUtilName;
procedure CONF_modules_finish;cdecl; external DLLUtilName;
function  CONF_module_add(name:pbyte; ifunc:Tconf_init_func; ffunc:Tconf_finish_func):cint;cdecl; external DLLUtilName;
function  CONF_imodule_get_name(md:PCONF_IMODULE):pbyte;cdecl; external DLLUtilName;
function  CONF_imodule_get_value(md:PCONF_IMODULE):pbyte;cdecl; external DLLUtilName;
function  CONF_imodule_get_usr_data(md:PCONF_IMODULE):pointer;cdecl; external DLLUtilName;
procedure CONF_imodule_set_usr_data(md:PCONF_IMODULE; usr_data:pointer);cdecl; external DLLUtilName;
function  CONF_imodule_get_module(md:PCONF_IMODULE):PCONF_MODULE;cdecl; external DLLUtilName;
function  CONF_imodule_get_flags(md:PCONF_IMODULE):culong;cdecl; external DLLUtilName;
procedure CONF_imodule_set_flags(md:PCONF_IMODULE; flags:culong);cdecl; external DLLUtilName;
function  CONF_module_get_usr_data(pmod:PCONF_MODULE):pointer;cdecl; external DLLUtilName;
procedure CONF_module_set_usr_data(pmod:PCONF_MODULE; usr_data:pointer);cdecl; external DLLUtilName;
function  CONF_get1_default_config_file:pbyte;cdecl; external DLLUtilName;
function  CONF_parse_list(list:pbyte; sep:cint; nospc:cint; list_cb:TCONF_list_cb; arg:pointer):cint;cdecl; external DLLUtilName;
procedure OPENSSL_load_builtin_modules;cdecl; external DLLUtilName;
function  ERR_load_CONF_strings:cint;cdecl; external DLLUtilName;
    const
      CONF_F_CONF_DUMP_FP = 104;      
      CONF_F_CONF_LOAD = 100;      
      CONF_F_CONF_LOAD_FP = 103;      
      CONF_F_CONF_PARSE_LIST = 119;      
      CONF_F_DEF_LOAD = 120;      
      CONF_F_DEF_LOAD_BIO = 121;      
      CONF_F_MODULE_INIT = 115;      
      CONF_F_MODULE_LOAD_DSO = 117;      
      CONF_F_MODULE_RUN = 118;      
      CONF_F_NCONF_DUMP_BIO = 105;      
      CONF_F_NCONF_DUMP_FP = 106;      
      CONF_F_NCONF_GET_NUMBER_E = 112;      
      CONF_F_NCONF_GET_SECTION = 108;      
      CONF_F_NCONF_GET_STRING = 109;      
      CONF_F_NCONF_LOAD = 113;      
      CONF_F_NCONF_LOAD_BIO = 110;      
      CONF_F_NCONF_LOAD_FP = 114;      
      CONF_F_NCONF_NEW = 111;      
      CONF_F_STR_COPY = 101;      
      CONF_R_ERROR_LOADING_DSO = 110;      
      CONF_R_LIST_CANNOT_BE_NULL = 115;      
      CONF_R_MISSING_CLOSE_SQUARE_BRACKET = 100;      
      CONF_R_MISSING_EQUAL_SIGN = 101;      
      CONF_R_MISSING_INIT_FUNCTION = 112;      
      CONF_R_MODULE_INITIALIZATION_ERROR = 109;      
      CONF_R_NO_CLOSE_BRACE = 102;      
      CONF_R_NO_CONF = 105;      
      CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE = 106;      
      CONF_R_NO_SECTION = 107;      
      CONF_R_NO_SUCH_FILE = 114;      
      CONF_R_NO_VALUE = 108;      
      CONF_R_UNABLE_TO_CREATE_NEW_SECTION = 103;      
      CONF_R_UNKNOWN_MODULE_NAME = 113;      
      CONF_R_VARIABLE_EXPANSION_TOO_LONG = 116;      
      CONF_R_VARIABLE_HAS_NO_VALUE = 104;

implementation

    Function OPENSSL_FILE:PByte; inline;
    begin
     PChar(Result):={$I %FILE%};
    end;

    Function OPENSSL_LINE:cint; inline;
    begin
     Result:={$I %LINENUM%};
    end;

    function  OPENSSL_malloc_init : cint; inline;
    begin
      OPENSSL_malloc_init:=CRYPTO_set_mem_functions(@CRYPTO_malloc,@CRYPTO_realloc,@CRYPTO_free);
    end;

    function  OPENSSL_malloc(num : size_t) : Pointer; inline;
    begin
      OPENSSL_malloc:=CRYPTO_malloc(num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_zalloc(num : size_t) : Pointer; inline;
    begin
      OPENSSL_zalloc:=CRYPTO_zalloc(num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_realloc(addr:Pointer;num : size_t) : Pointer; inline;
    begin
      OPENSSL_realloc:=CRYPTO_realloc(addr,num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_clear_realloc(addr:Pointer;old_num,num : size_t) : Pointer; inline;
    begin
      OPENSSL_clear_realloc:=CRYPTO_clear_realloc(addr,old_num,num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  OPENSSL_clear_free(addr:Pointer;num : size_t); inline;
    begin
      CRYPTO_clear_free(addr,num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  OPENSSL_free(addr : Pointer); inline;
    begin
      CRYPTO_free(addr,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_memdup(str:Pointer;s : size_t) : Pointer; inline;
    begin
      OPENSSL_memdup:=CRYPTO_memdup(str,s,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_strdup(str : pbyte) : pbyte;  inline;
    begin
      OPENSSL_strdup:=CRYPTO_strdup(str,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_strndup(str : pbyte;n : size_t) : pbyte; inline;
    begin
      OPENSSL_strndup:=CRYPTO_strndup(str,n,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_secure_malloc(num : size_t) : Pointer; inline;
    begin
      OPENSSL_secure_malloc:=CRYPTO_secure_malloc(num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_secure_zalloc(num : size_t) : Pointer; inline;
    begin
      OPENSSL_secure_zalloc:=CRYPTO_secure_zalloc(num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure OPENSSL_secure_free(addr : Pointer); inline;
    begin
      CRYPTO_secure_free(addr,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure OPENSSL_secure_clear_free(addr:Pointer;num : longint); inline;
    begin
      CRYPTO_secure_clear_free(addr,num,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_secure_actual_size(ptr : Pointer) : size_t; inline;
    begin
      OPENSSL_secure_actual_size:=CRYPTO_secure_actual_size(ptr);
    end;

    function  OPENSSL_MALLOC_MAX_NELEMS(SizeOf_type : longint) : longint; inline;
    begin
      OPENSSL_MALLOC_MAX_NELEMS:=((1 shl (((sizeof(cint))*8)-1))-1) div SizeOf_type;
    end;

    function  OPENSSL_mem_debug_push(info : Pbyte) : cint; inline;
    begin
      OPENSSL_mem_debug_push:=CRYPTO_mem_debug_push(info,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  OPENSSL_mem_debug_pop : longint; inline;
    begin
      OPENSSL_mem_debug_pop:=CRYPTO_mem_debug_pop;
    end;

    Procedure  OpenSSLDie(f:PByte;l:cint;a:Pointer); inline;
    begin
      OPENSSL_die(a,f,l);
    end;

    function  BIO_get_flags(b : PBIO) : cint; inline;
    begin
      BIO_get_flags:=BIO_test_flags(b, not ($0));
    end;

    Procedure BIO_set_retry_special(b : PBIO); inline;
    begin
      BIO_set_flags(b,BIO_FLAGS_IO_SPECIAL or BIO_FLAGS_SHOULD_RETRY);
    end;

    Procedure BIO_set_retry_read(b : PBIO); inline;
    begin
      BIO_set_flags(b,BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
    end;

    Procedure BIO_set_retry_write(b : PBIO); inline;
    begin
      BIO_set_flags(b,BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
    end;

    Procedure BIO_clear_retry_flags(b : PBIO); inline;
    begin
      BIO_clear_flags(b,BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
    end;

    function  BIO_get_retry_flags(b : PBIO) : cint; inline;
    begin
      BIO_get_retry_flags:=BIO_test_flags(b,BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
    end;

    function  BIO_should_read(a : PBIO) : cint; inline;
    begin
      BIO_should_read:=BIO_test_flags(a,BIO_FLAGS_READ);
    end;

    function  BIO_should_write(a : PBIO) : cint; inline;
    begin
      BIO_should_write:=BIO_test_flags(a,BIO_FLAGS_WRITE);
    end;

    function  BIO_should_io_special(a : PBIO) : cint; inline;
    begin
      BIO_should_io_special:=BIO_test_flags(a,BIO_FLAGS_IO_SPECIAL);
    end;

    function  BIO_retry_type(a : PBIO) : cint; inline;
    begin
      BIO_retry_type:=BIO_test_flags(a,BIO_FLAGS_RWS);
    end;

    function  BIO_should_retry(a : PBIO) : cint; inline;
    begin
      BIO_should_retry:=BIO_test_flags(a,BIO_FLAGS_SHOULD_RETRY);
    end;

    function  BIO_set_app_data(s : PBIO;arg : Pointer) : cint; inline;
    begin
      BIO_set_app_data:=BIO_set_ex_data(s,0,arg);
    end;

    function  BIO_get_app_data(s : PBIO) : Pointer; inline;
    begin
      BIO_get_app_data:=BIO_get_ex_data(s,0);
    end;

    function  BIO_set_nbio(b : PBIO;n : clong) : clong; inline;
    begin
      BIO_set_nbio:=BIO_ctrl(b,BIO_C_SET_NBIO,n,nil);
    end;

    function  BIO_set_conn_hostname(b : PBIO;name : Pointer) : clong; inline;
    begin
      BIO_set_conn_hostname:=BIO_ctrl(b,BIO_C_SET_CONNECT,0,name);
    end;

    function  BIO_set_conn_port(b : PBIO;port : Pointer) : clong; inline;
    begin
      BIO_set_conn_port:=BIO_ctrl(b,BIO_C_SET_CONNECT,1,port);
    end;

    function  BIO_set_conn_address(b : PBIO;addr : Pointer) : clong; inline;
    begin
      BIO_set_conn_address:=BIO_ctrl(b,BIO_C_SET_CONNECT,2,addr);
    end;

    function  BIO_set_conn_ip_family(b : PBIO;f : cint) : clong; inline;
    begin
      BIO_set_conn_ip_family:=BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f);
    end;

    function  BIO_get_conn_hostname(b : PBIO) : Pointer; inline;
    begin
      BIO_get_conn_hostname:=pbyte(BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0));
    end;

    function  BIO_get_conn_port(b : PBIO) : Pointer; inline;
    begin
      BIO_get_conn_port:=pbyte(BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1));
    end;

    function  BIO_get_conn_address(b : PBIO) : Pointer; inline;
    begin
      BIO_get_conn_address:=BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2);
    end;

    function  BIO_get_conn_ip_family(b : PBIO) : clong; inline;
    begin
      BIO_get_conn_ip_family:=BIO_ctrl(b,BIO_C_GET_CONNECT,3,nil);
    end;

    function  BIO_set_conn_mode(b : PBIO;n : clong) : clong; inline;
    begin
      BIO_set_conn_mode:=BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,n,nil);
    end;

    function  BIO_set_accept_name(b : PBIO;name : Pointer) : clong; inline;
    begin
      BIO_set_accept_name:=BIO_ctrl(b,BIO_C_SET_ACCEPT,0,name);
    end;

    function  BIO_set_accept_port(b : PBIO;port : Pointer) : clong; inline;
    begin
      BIO_set_accept_port:=BIO_ctrl(b,BIO_C_SET_ACCEPT,1,port);
    end;

    function  BIO_get_accept_name(b : PBIO) : Pointer; inline;
    begin
      BIO_get_accept_name:=BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0);
    end;

    function  BIO_get_accept_port(b : PBIO) : Pointer; inline;
    begin
      BIO_get_accept_port:=BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1);
    end;

    function  BIO_get_peer_name(b : PBIO) : Pointer; inline;
    begin
      BIO_get_peer_name:=BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2);
    end;

    function  BIO_get_peer_port(b : PBIO) : Pointer; inline;
    begin
      BIO_get_peer_port:=BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3);
    end;

    function  BIO_set_nbio_accept(b : PBIO;n : Pointer) : clong; inline;
    begin
      BIO_set_nbio_accept:=BIO_ctrl(b,BIO_C_SET_ACCEPT,2,n);
    end;

    function  BIO_set_accept_bios(b : PBIO;bio : Pointer) : clong; inline;
    begin
      BIO_set_accept_bios:=BIO_ctrl(b,BIO_C_SET_ACCEPT,3,bio);
    end;

    function  BIO_set_accept_ip_family(b : PBIO;f : cint) : clong; inline;
    begin
      BIO_set_accept_ip_family:=BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f);
    end;

    function  BIO_get_accept_ip_family(b : PBIO) : clong; inline;
    begin
      BIO_get_accept_ip_family:=BIO_ctrl(b,BIO_C_GET_ACCEPT,4,nil);
    end;

    function  BIO_set_bind_mode(b : PBIO;mode : clong) : clong; inline;
    begin
      BIO_set_bind_mode:=BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,nil);
    end;

    function  BIO_get_bind_mode(b : PBIO) : clong; inline;
    begin
      BIO_get_bind_mode:=BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,nil);
    end;

    function  BIO_do_connect(b : PBIO) : clong; inline;
    begin
      BIO_do_connect:=BIO_do_handshake(b);
    end;

    function  BIO_do_accept(b : PBIO) : clong; inline;
    begin
      BIO_do_accept:=BIO_do_handshake(b);
    end;

    function  BIO_do_handshake(b : PBIO) : clong; inline;
    begin
      BIO_do_handshake:=BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,nil);
    end;

    function  BIO_set_fd(b : PBIO;fd,c : clong) : clong; inline;
    begin
      BIO_set_fd:=BIO_int_ctrl(b,BIO_C_SET_FD,c,fd);
    end;

    function  BIO_get_fd(b : PBIO;c : Pointer) : clong; inline;
    begin
      BIO_get_fd:=BIO_ctrl(b,BIO_C_GET_FD,0,c);
    end;

    function  BIO_set_fp(b : PBIO;fp : Pointer;c : clong) : clong; inline;
    begin
      BIO_set_fp:=BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,fp);
    end;

    function  BIO_get_fp(b : PBIO;fpp : Pointer) : clong; inline;
    begin
      BIO_get_fp:=BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,fpp);
    end;

    function  BIO_seek(b : PBIO;ofs : clong) : clong; inline;
    begin
      BIO_seek:=BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,nil);
    end;

    function  BIO_tell(b : PBIO) : clong; inline;
    begin
      BIO_tell:=BIO_ctrl(b,BIO_C_FILE_TELL,0,nil);
    end;

    function  BIO_read_filename(b : PBIO;name : Pointer) : clong; inline;
    begin
      BIO_read_filename:=BIO_ctrl(b,BIO_C_SET_FILENAME,BIO_CLOSE or BIO_FP_READ,name);
    end;

    function  BIO_write_filename(b : PBIO;name : Pointer) : clong; inline;
    begin
      BIO_write_filename:=BIO_ctrl(b,BIO_C_SET_FILENAME,BIO_CLOSE or BIO_FP_WRITE,name);
    end;

    function  BIO_append_filename(b : PBIO;name : Pointer) : clong; inline;
    begin
      BIO_append_filename:=BIO_ctrl(b,BIO_C_SET_FILENAME,BIO_CLOSE or BIO_FP_APPEND,name);
    end;

    function  BIO_rw_filename(b : PBIO;name : Pointer) : clong; inline;
    begin
      BIO_rw_filename:=BIO_ctrl(b,BIO_C_SET_FILENAME,(BIO_CLOSE or BIO_FP_READ) or BIO_FP_WRITE,name);
    end;

    function  BIO_set_ssl(b : PBIO;ssl:Pointer;c : clong) : clong; inline;
    begin
      BIO_set_ssl:=BIO_ctrl(b,BIO_C_SET_SSL,c,ssl);
    end;

    function  BIO_get_ssl(b : PBIO;sslp : Pointer) : clong; inline;
    begin
      BIO_get_ssl:=BIO_ctrl(b,BIO_C_GET_SSL,0,sslp);
    end;

    function  BIO_set_ssl_mode(b : PBIO;client : clong) : clong; inline;
    begin
      BIO_set_ssl_mode:=BIO_ctrl(b,BIO_C_SSL_MODE,client,nil);
    end;

    function  BIO_set_ssl_renegotiate_bytes(b : PBIO;num : clong) : clong; inline;
    begin
      BIO_set_ssl_renegotiate_bytes:=BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,nil);
    end;

    function  BIO_get_num_renegotiates(b : PBIO) : clong; inline;
    begin
      BIO_get_num_renegotiates:=BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,nil);
    end;

    function  BIO_set_ssl_renegotiate_timeout(b : PBIO;seconds : clong) : clong; inline;
    begin
      BIO_set_ssl_renegotiate_timeout:=BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,nil);
    end;

    function  BIO_get_mem_data(b : PBIO;pp : Pointer) : clong; inline;
    begin
      BIO_get_mem_data:=BIO_ctrl(b,BIO_CTRL_INFO,0,pp);
    end;

    function  BIO_set_mem_buf(b : PBIO;bm : Pointer;c : clong) : clong; inline;
    begin
      BIO_set_mem_buf:=BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,bm);
    end;

    function  BIO_get_mem_ptr(b : PBIO;pp : Pointer) : clong; inline;
    begin
      BIO_get_mem_ptr:=BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,pp);
    end;

    function  BIO_set_mem_eof_return(b : PBIO;v : clong) : clong; inline;
    begin
      BIO_set_mem_eof_return:=BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,nil);
    end;

    function  BIO_get_buffer_num_lines(b : PBIO) : clong; inline;
    begin
      BIO_get_buffer_num_lines:=BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,nil);
    end;

    function  BIO_set_buffer_size(b : PBIO;size : clong) : clong; inline;
    begin
      BIO_set_buffer_size:=BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,nil);
    end;

    function  BIO_set_read_buffer_size(b : PBIO;size : clong) : clong; inline;
    begin
      BIO_set_read_buffer_size:=BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0);
    end;

    function  BIO_set_write_buffer_size(b : PBIO;size : clong) : clong; inline;
    begin
      BIO_set_write_buffer_size:=BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1);
    end;

    function  BIO_set_buffer_read_data(b : PBIO;buf:Pointer;num : clong) : clong; inline;
    begin
      BIO_set_buffer_read_data:=BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf);
    end;

    function  BIO_dup_state(b : PBIO;ret : Pointer) : clong; inline;
    begin
      BIO_dup_state:=BIO_ctrl(b,BIO_CTRL_DUP,0,ret);
    end;

    function  BIO_reset(b : PBIO) : clong; inline;
    begin
      BIO_reset:=BIO_ctrl(b,BIO_CTRL_RESET,0,nil);
    end;

    function  BIO_eof(b : PBIO) : clong; inline;
    begin
      BIO_eof:=cint(BIO_ctrl(b,BIO_CTRL_EOF,0,nil));
    end;

    function  BIO_set_close(b : PBIO;c : clong) : clong; inline;
    begin
      BIO_set_close:=BIO_ctrl(b,BIO_CTRL_SET_CLOSE,c,nil);
    end;

    function  BIO_get_close(b : PBIO) : clong; inline;
    begin
      BIO_get_close:=cint(BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,nil));
    end;

    function  BIO_pending(b : PBIO) : clong; inline;
    begin
      BIO_pending:=BIO_ctrl(b,_BIO_CTRL_PENDING,0,nil);
    end;

    function  BIO_wpending(b : PBIO) : clong; inline;
    begin
      BIO_wpending:=BIO_ctrl(b,_BIO_CTRL_WPENDING,0,nil);
    end;

    function  BIO_flush(b : PBIO) : clong; inline;
    begin
      BIO_flush:=BIO_ctrl(b,BIO_CTRL_FLUSH,0,nil);
    end;

    function  BIO_get_info_callback(b : PBIO;cbp : Pointer) : clong; inline;
    begin
      BIO_get_info_callback:=BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0,cbp);
    end;

    function  BIO_set_info_callback(b : PBIO;cb : Tbio_callback_ctrl_func) : clong; inline;
    begin
      BIO_set_info_callback:=BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb);
    end;

    function  BIO_buffer_get_num_lines(b : PBIO) : clong; inline;
    begin
      BIO_buffer_get_num_lines:=BIO_ctrl(b,BIO_CTRL_GET,0,nil);
    end;

    function  BIO_set_write_buf_size(b : PBIO;size : clong) : clong; inline;
    begin
      BIO_set_write_buf_size:=BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,nil);
    end;

    function  BIO_get_write_buf_size(b : PBIO;size : clong) : clong; inline;
    begin
      BIO_get_write_buf_size:=BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,nil);
    end;

    function  BIO_make_bio_pair(b1,b2 : PBIO) : clong; inline;
    begin
      BIO_make_bio_pair:=BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2);
    end;

    function  BIO_destroy_bio_pair(b : PBIO) : clong; inline;
    begin
      BIO_destroy_bio_pair:=BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,nil);
    end;

    function  BIO_shutdown_wr(b : PBIO) : clong; inline;
    begin
      BIO_shutdown_wr:=BIO_ctrl(b,BIO_C_SHUTDOWN_WR,0,nil);
    end;

    function  BIO_get_write_guarantee(b : PBIO) : clong; inline;
    begin
      BIO_get_write_guarantee:=BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,nil);
    end;

    function  BIO_get_read_request(b : PBIO) : clong; inline;
    begin
      BIO_get_read_request:=BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,nil);
    end;

    function  BIO_ctrl_dgram_connect(b : PBIO;peer : Pointer) : clong; inline;
    begin
      BIO_ctrl_dgram_connect:=BIO_ctrl(b,_BIO_CTRL_DGRAM_CONNECT,0,peer);
    end;

    function  BIO_ctrl_set_connected(b : PBIO;peer : Pointer) : clong; inline;
    begin
      BIO_ctrl_set_connected:=cint(BIO_ctrl(b,BIO_CTRL_DGRAM_SET_CONNECTED,0,pbyte(peer)));
    end;

    function  BIO_dgram_recv_timedout(b : PBIO) : clong; inline;
    begin
      BIO_dgram_recv_timedout:=cint(BIO_ctrl(b,BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP,0,nil));
    end;

    function  BIO_dgram_send_timedout(b : PBIO) : clong; inline;
    begin
      BIO_dgram_send_timedout:=BIO_ctrl(b,BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP,0,nil);
    end;

    function  BIO_dgram_get_peer(b : PBIO;peer : Pointer) : clong; inline;
    begin
      BIO_dgram_get_peer:=BIO_ctrl(b,BIO_CTRL_DGRAM_GET_PEER,0,peer);
    end;

    function  BIO_dgram_set_peer(b : PBIO;peer : Pointer) : clong; inline;
    begin
      BIO_dgram_set_peer:=BIO_ctrl(b,BIO_CTRL_DGRAM_SET_PEER,0,peer);
    end;

    function  BIO_dgram_get_mtu_overhead(b : PBIO) : clong; inline;
    begin
      BIO_dgram_get_mtu_overhead:=BIO_ctrl(b,BIO_CTRL_DGRAM_GET_MTU_OVERHEAD,0,nil);
    end;

    function  BIO_get_ex_new_index(argl:clong; argp:pointer; new_func:TCRYPTO_EX_new; dup_func:TCRYPTO_EX_dup;free_func:TCRYPTO_EX_free) : cint; inline;
    begin
      BIO_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO,argl,argp,new_func,dup_func,free_func);
    end;

    function  BUF_strdup(s : pbyte) : pbyte; inline;
    begin
      BUF_strdup:=OPENSSL_strdup(s);
    end;

    function  BUF_strndup(s:pbyte;size : size_t) : pbyte; inline;
    begin
      BUF_strndup:=OPENSSL_strndup(s,size);
    end;

    function  BUF_memdup(data:Pointer;size : size_t) : Pointer; inline;
    begin
      BUF_memdup:=OPENSSL_memdup(data,size);
    end;

    function  BUF_strlcpy(dst,src:PByte;size : size_t) : size_t; inline;
    begin
      BUF_strlcpy:=OPENSSL_strlcpy(dst,src,size);
    end;

    function  BUF_strlcat(dst,src:PByte;size : size_t) : size_t; inline;
    begin
      BUF_strlcat:=OPENSSL_strlcat(dst,src,size);
    end;

    function  BUF_strnlen(str:PByte;maxlen : size_t) : size_t; inline;
    begin
      BUF_strnlen:=OPENSSL_strnlen(str,maxlen);
    end;

    function  BN_num_bytes(a : PBIGNUM) : cint; inline;
    begin
      BN_num_bytes:=((BN_num_bits(a))+7) div 8;
    end;

    function  BN_one(a : PBIGNUM) : cint; inline;
    begin
      BN_one:=BN_set_word(a,1);
    end;

    function  BN_zero(a : PBIGNUM) : cint; inline;
    begin
      BN_zero:=BN_set_word(a,0);
    end;

    function  BN_mod(rem,m,d : PBIGNUM;ctx : PBN_CTX) : cint; inline;
    begin
      BN_mod:=BN_div(nil,rem,m,d,ctx);
    end;

    function  BN_GF2m_sub(r,a,b : PBIGNUM) : cint; inline;
    begin
      BN_GF2m_sub:=BN_GF2m_add(r,a,b);
    end;

    function  BN_GF2m_cmp(a,b : PBIGNUM) : cint; inline;
    begin
      BN_GF2m_cmp:=BN_ucmp(a,b);
    end;

    function  OBJ_create_and_add_object(a,b,c : pbyte) : cint; inline;
    begin
      OBJ_create_and_add_object:=OBJ_create(a,b,c);
    end;

    function  EVP_PKEY_assign_RSA(pkey:PEVP_PKEY;rsa : Pointer) : cint; inline;
    begin
      EVP_PKEY_assign_RSA:=EVP_PKEY_assign(pkey,EVP_PKEY_RSA,rsa);
    end;

    function  EVP_PKEY_assign_DSA(pkey:PEVP_PKEY;dsa : Pointer) : cint; inline;
    begin
      EVP_PKEY_assign_DSA:=EVP_PKEY_assign(pkey,EVP_PKEY_DSA,dsa);
    end;

    function  EVP_PKEY_assign_DH(pkey:PEVP_PKEY;dh : Pointer) : cint; inline;
    begin
      EVP_PKEY_assign_DH:=EVP_PKEY_assign(pkey,EVP_PKEY_DH,dh);
    end;

    function  EVP_PKEY_assign_EC_KEY(pkey:PEVP_PKEY;eckey : Pointer) : cint; inline;
    begin
      EVP_PKEY_assign_EC_KEY:=EVP_PKEY_assign(pkey,EVP_PKEY_EC,eckey);
    end;

    function  EVP_get_digestbynid(a : cint) : PEVP_MD; inline;
    begin
      EVP_get_digestbynid:=EVP_get_digestbyname(OBJ_nid2sn(a));
    end;

    function  EVP_get_digestbyobj(a : PASN1_OBJECT) : PEVP_MD; inline;
    begin
      EVP_get_digestbyobj:=EVP_get_digestbynid(OBJ_obj2nid(a));
    end;

    function  EVP_get_cipherbynid(a : cint) : PEVP_CIPHER; inline;
    begin
      EVP_get_cipherbynid:=EVP_get_cipherbyname(OBJ_nid2sn(a));
    end;

    function  EVP_get_cipherbyobj(a : PASN1_OBJECT) : PEVP_CIPHER; inline;
    begin
      EVP_get_cipherbyobj:=EVP_get_cipherbynid(OBJ_obj2nid(a));
    end;

    function  EVP_MD_nid(e : PEVP_MD) : cint; inline;
    begin
      EVP_MD_nid:=EVP_MD_type(e);
    end;

    function  EVP_MD_name(e : PEVP_MD) : PByte; inline;
    begin
      EVP_MD_name:=OBJ_nid2sn(EVP_MD_nid(e));
    end;

    function  EVP_MD_CTX_size(e : PEVP_MD_CTX) : cint; inline;
    begin
      EVP_MD_CTX_size:=EVP_MD_size(EVP_MD_CTX_md(e));
    end;

    function  EVP_MD_CTX_block_size(e : PEVP_MD_CTX) : cint; inline;
    begin
      EVP_MD_CTX_block_size:=EVP_MD_block_size(EVP_MD_CTX_md(e));
    end;

    function  EVP_MD_CTX_type(e : PEVP_MD_CTX) : cint; inline;
    begin
      EVP_MD_CTX_type:=EVP_MD_type(EVP_MD_CTX_md(e));
    end;

    function  EVP_CIPHER_name(e : PEVP_CIPHER) : PByte; inline;
    begin
      EVP_CIPHER_name:=OBJ_nid2sn(EVP_CIPHER_nid(e));
    end;

    function  EVP_CIPHER_mode(e : PEVP_CIPHER) : Boolean; inline;
    begin
      EVP_CIPHER_mode:=(EVP_CIPHER_flags(e)) and EVP_CIPH_MODE<>0;
    end;

    function  EVP_CIPHER_CTX_type(c : PEVP_CIPHER_CTX) : cint; inline;
    begin
      EVP_CIPHER_CTX_type:=EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c));
    end;

    function  EVP_CIPHER_CTX_flags(c : PEVP_CIPHER_CTX) : culong; inline;
    begin
      EVP_CIPHER_CTX_flags:=EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c));
    end;

    function  EVP_CIPHER_CTX_mode(c : PEVP_CIPHER_CTX) : Boolean; inline;
    begin
      EVP_CIPHER_CTX_mode:=EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c));
    end;

    function  EVP_ENCODE_LENGTH(l : longint) : longint; inline;
    begin
      EVP_ENCODE_LENGTH:=((((l+2) div 3)*4)+(((l div 48)+1)*2))+80;
    end;

    function  EVP_DECODE_LENGTH(l : longint) : longint; inline;
    begin
      EVP_DECODE_LENGTH:=(((l+3) div 4)*3)+80;
    end;

    function  EVP_SignInit_ex(a:PEVP_MD_CTX;b:PEVP_MD;c:PENGINE) : cint; inline;
    begin
      EVP_SignInit_ex:=EVP_DigestInit_ex(a,b,c);
    end;

    function  EVP_SignInit(a:PEVP_MD_CTX;b:PEVP_MD) : cint; inline;
    begin
      EVP_SignInit:=EVP_DigestInit(a,b);
    end;

    function  EVP_SignUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t) : cint; inline;
    begin
      EVP_SignUpdate:=EVP_DigestUpdate(a,b,c);
    end;

    function  EVP_VerifyInit_ex(a:PEVP_MD_CTX;b:PEVP_MD;c:PENGINE) : cint; inline;
    begin
      EVP_VerifyInit_ex:=EVP_DigestInit_ex(a,b,c);
    end;

    function  EVP_VerifyInit(a:PEVP_MD_CTX;b:PEVP_MD) : cint; inline;
    begin
      EVP_VerifyInit:=EVP_DigestInit(a,b);
    end;

    function  EVP_VerifyUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t) : cint; inline;
    begin
      EVP_VerifyUpdate:=EVP_DigestUpdate(a,b,c);
    end;

    function  EVP_OpenUpdate(a:PEVP_CIPHER_CTX;b:pbyte;c:pcint;d:pbyte;e:cint) : cint; inline;
    begin
      EVP_OpenUpdate:=EVP_DecryptUpdate(a,b,c,d,e);
    end;

    function  EVP_SealUpdate(a:PEVP_CIPHER_CTX;b:pbyte;c:pcint;d:pbyte;e:cint) : cint; inline;
    begin
      EVP_SealUpdate:=EVP_EncryptUpdate(a,b,c,d,e);
    end;

    function  EVP_DigestSignUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t):cint; inline;
    begin
      EVP_DigestSignUpdate:=EVP_DigestUpdate(a,b,c);
    end;

    function  EVP_DigestVerifyUpdate(a:PEVP_MD_CTX;b:pointer;c:size_t) : cint; inline;
    begin
      EVP_DigestVerifyUpdate:=EVP_DigestUpdate(a,b,c);
    end;

    function  BIO_set_md(b:PBIO;md : Pointer) : clong; inline;
    begin
      BIO_set_md:=BIO_ctrl(b,BIO_C_SET_MD,0,md);
    end;

    function  BIO_get_md(b:PBIO;mdp : Pointer) : clong; inline;
    begin
      BIO_get_md:=BIO_ctrl(b,BIO_C_GET_MD,0,mdp);
    end;

    function  BIO_get_md_ctx(b:PBIO;mdcp : Pointer) : clong; inline;
    begin
      BIO_get_md_ctx:=BIO_ctrl(b,BIO_C_GET_MD_CTX,0,mdcp);
    end;

    function  BIO_set_md_ctx(b:PBIO;mdcp : Pointer) : clong; inline;
    begin
      BIO_set_md_ctx:=BIO_ctrl(b,BIO_C_SET_MD_CTX,0,mdcp);
    end;

    function  BIO_get_cipher_status(b : PBIO) : clong; inline;
    begin
      BIO_get_cipher_status:=BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,nil);
    end;

    function  BIO_get_cipher_ctx(b : PBIO;c_pp : Pointer) : clong; inline;
    begin
      BIO_get_cipher_ctx:=BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,c_pp);
    end;

    function  EVP_add_cipher_alias(n,_alias : PByte) : cint; inline;
    begin
      EVP_add_cipher_alias:=OBJ_NAME_add(_alias,OBJ_NAME_TYPE_CIPHER_METH or OBJ_NAME_ALIAS,n);
    end;

    function  EVP_add_digest_alias(n,_alias : PByte) : cint; inline;
    begin
      EVP_add_digest_alias:=OBJ_NAME_add(_alias,OBJ_NAME_TYPE_MD_METH or OBJ_NAME_ALIAS,n);
    end;

    function  EVP_MD_CTX_create : PEVP_MD_CTX; inline;
    begin
      EVP_MD_CTX_create:=EVP_MD_CTX_new;
    end;

    function  EVP_MD_CTX_init(ctx : PEVP_MD_CTX) : cint; inline;
    begin
      EVP_MD_CTX_init:=EVP_MD_CTX_reset(ctx);
    end;

    Procedure EVP_MD_CTX_destroy(ctx : PEVP_MD_CTX); inline;
    begin
      EVP_MD_CTX_free(ctx);
    end;

    function  EVP_CIPHER_CTX_init(c : PEVP_CIPHER_CTX) : cint; inline;
    begin
      EVP_CIPHER_CTX_init:=EVP_CIPHER_CTX_reset(c);
    end;

    function  EVP_CIPHER_CTX_cleanup(c : PEVP_CIPHER_CTX) : cint; inline;
    begin
      EVP_CIPHER_CTX_cleanup:=EVP_CIPHER_CTX_reset(c);
    end;

    function  OPENSSL_add_all_algorithms_conf : cint; inline;
    begin
      OPENSSL_add_all_algorithms_conf:=OPENSSL_init_crypto((OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS) or OPENSSL_INIT_LOAD_CONFIG,nil);
    end;

    function  OPENSSL_add_all_algorithms_noconf : cint; inline;
    begin
      OPENSSL_add_all_algorithms_noconf:=OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS,nil);
    end;

    function  OpenSSL_add_all_algorithms : cint; inline;
    begin
      OpenSSL_add_all_algorithms:=OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS,nil);
    end;

    function  OpenSSL_add_all_ciphers : cint; inline;
    begin
      OpenSSL_add_all_ciphers:=OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS,nil);
    end;

    function  OpenSSL_add_all_digests : cint; inline;
    begin
      OpenSSL_add_all_digests:=OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS,nil);
    end;

    function  EVP_PKEY_CTX_set_signature_md(ctx:PEVP_PKEY_CTX;md : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_set_signature_md:=EVP_PKEY_CTX_ctrl(ctx,-(1),EVP_PKEY_OP_TYPE_SIG,EVP_PKEY_CTRL_MD,0,md);
    end;

    function  EVP_PKEY_CTX_get_signature_md(ctx:PEVP_PKEY_CTX;pmd : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_signature_md:=EVP_PKEY_CTX_ctrl(ctx,-(1),EVP_PKEY_OP_TYPE_SIG,EVP_PKEY_CTRL_GET_MD,0,pmd);
    end;

    function  EVP_PKEY_CTX_set_mac_key(ctx:PEVP_PKEY_CTX;key:Pointer;len:cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_mac_key:=EVP_PKEY_CTX_ctrl(ctx,-(1),EVP_PKEY_OP_KEYGEN,EVP_PKEY_CTRL_SET_MAC_KEY,len,key);
    end;

    function  d2i_ECPKParameters_bio(bp:PBIO;x:Ppointer):Pointer; inline;
    begin
      d2i_ECPKParameters_bio:=ASN1_d2i_bio(nil,@d2i_ECPKParameters,bp,x);
    end;

    function  i2d_ECPKParameters_bio(bp:PBIO;x:pbyte):cint; inline;
    begin
      i2d_ECPKParameters_bio:=ASN1_i2d_bio(@i2d_ECPKParameters,bp,x);
    end;

    function  EC_KEY_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free) : cint; inline;
    begin
      EC_KEY_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY,l,p,newf,dupf,freef);
    end;

    function  ECParameters_dup(x : Pointer) : Pointer; inline;
    begin
      ECParameters_dup:=ASN1_dup(@i2d_ECParameters,@d2i_ECParameters,x);
    end;

    function  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx:PEVP_PKEY_CTX;nid : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN,EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,nid,nil);
    end;

    function  EVP_PKEY_CTX_set_ec_param_enc(ctx:PEVP_PKEY_CTX;flag : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_ec_param_enc:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN,EVP_PKEY_CTRL_EC_PARAM_ENC,flag,nil);
    end;

    function  EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx:PEVP_PKEY_CTX;flag : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_ecdh_cofactor_mode:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_EC_ECDH_COFACTOR,flag,nil);
    end;

    function  EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx : PEVP_PKEY_CTX) : cint; inline;
    begin
      EVP_PKEY_CTX_get_ecdh_cofactor_mode:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_EC_ECDH_COFACTOR,-(2),nil);
    end;

    function  EVP_PKEY_CTX_set_ecdh_kdf_type(ctx : PEVP_PKEY_CTX;kdf : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_ecdh_kdf_type:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_EC_KDF_TYPE,kdf,nil);
    end;

    function  EVP_PKEY_CTX_get_ecdh_kdf_type(ctx : PEVP_PKEY_CTX) : cint; inline;
    begin
      EVP_PKEY_CTX_get_ecdh_kdf_type:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_EC_KDF_TYPE,-(2),nil);
    end;

    function  EVP_PKEY_CTX_set_ecdh_kdf_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_set_ecdh_kdf_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_EC_KDF_MD,0,md);
    end;

    function  EVP_PKEY_CTX_get_ecdh_kdf_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_ecdh_kdf_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_GET_EC_KDF_MD,0,pmd);
    end;

    function  EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx : PEVP_PKEY_CTX;len : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_ecdh_kdf_outlen:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_EC_KDF_OUTLEN,len,nil);
    end;

    function  EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx : PEVP_PKEY_CTX;plen : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_ecdh_kdf_outlen:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN,0,plen);
    end;

    function  EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx : PEVP_PKEY_CTX;p:Pointer;plen : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set0_ecdh_kdf_ukm:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_EC_KDF_UKM,plen,p);
    end;

    function  EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx : PEVP_PKEY_CTX;p : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get0_ecdh_kdf_ukm:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_EC,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_GET_EC_KDF_UKM,0,p);
    end;

    function  EVP_PKEY_CTX_set_rsa_padding(ctx : PEVP_PKEY_CTX;pad : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_rsa_padding:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,-(1),EVP_PKEY_CTRL_RSA_PADDING,pad,nil);
    end;

    function  EVP_PKEY_CTX_get_rsa_padding(ctx : PEVP_PKEY_CTX;ppad : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_rsa_padding:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,-(1),EVP_PKEY_CTRL_GET_RSA_PADDING,0,ppad);
    end;

    function  EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx : PEVP_PKEY_CTX;len : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_rsa_pss_saltlen:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY,EVP_PKEY_CTRL_RSA_PSS_SALTLEN,len,nil);
    end;

    function  EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx : PEVP_PKEY_CTX;plen : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_rsa_pss_saltlen:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY,EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN,0,plen);
    end;

    function  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx : PEVP_PKEY_CTX;bits : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_rsa_keygen_bits:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_KEYGEN,EVP_PKEY_CTRL_RSA_KEYGEN_BITS,bits,nil);
    end;

    function  EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx : PEVP_PKEY_CTX;pubexp : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_set_rsa_keygen_pubexp:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_KEYGEN,EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP,0,pubexp);
    end;

    function  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_set_rsa_mgf1_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT,EVP_PKEY_CTRL_RSA_MGF1_MD,0,md);
    end;

    function  EVP_PKEY_CTX_set_rsa_oaep_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_set_rsa_oaep_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_TYPE_CRYPT,EVP_PKEY_CTRL_RSA_OAEP_MD,0,md);
    end;

    function  EVP_PKEY_CTX_get_rsa_mgf1_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_rsa_mgf1_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT,EVP_PKEY_CTRL_GET_RSA_MGF1_MD,0,pmd);
    end;

    function  EVP_PKEY_CTX_get_rsa_oaep_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_rsa_oaep_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_TYPE_CRYPT,EVP_PKEY_CTRL_GET_RSA_OAEP_MD,0,pmd);
    end;

    function  EVP_PKEY_CTX_set0_rsa_oaep_label(ctx : PEVP_PKEY_CTX;l:Pointer;llen : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set0_rsa_oaep_label:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_TYPE_CRYPT,EVP_PKEY_CTRL_RSA_OAEP_LABEL,llen,l);
    end;

    function  EVP_PKEY_CTX_get0_rsa_oaep_label(ctx : PEVP_PKEY_CTX;l : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get0_rsa_oaep_label:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_RSA,EVP_PKEY_OP_TYPE_CRYPT,EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL,0,l);
    end;

    function  RSA_set_app_data(s:PRSA;arg:pointer) : cint; inline;
    begin
      RSA_set_app_data:=RSA_set_ex_data(s,0,arg);
    end;

    function  RSA_get_app_data(s : PRSA) : pointer; inline;
    begin
      RSA_get_app_data:=RSA_get_ex_data(s,0);
    end;

    function  RSA_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      RSA_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA,l,p,newf,dupf,freef);
    end;

    function  d2i_DHparams_bio(bp:PBIO;x:Ppointer) : Pointer; inline;
    begin
      d2i_DHparams_bio:=ASN1_d2i_bio(TPfunction(@DH_new),@d2i_DHparams,bp,x);
    end;

    function  i2d_DHparams_bio(bp:PBIO;x:PByte) : cint; inline;
    begin
      i2d_DHparams_bio:=ASN1_i2d_bio(@i2d_DHparams,bp,x);
    end;

    function  d2i_DHxparams_bio(bp:PBIO;x:Ppointer) : Pointer; inline;
    begin
      d2i_DHxparams_bio:=ASN1_d2i_bio(TPfunction(@DH_new),@d2i_DHxparams,bp,x);
    end;

    function  i2d_DHxparams_bio(bp:PBIO;x:PByte) : cint; inline;
    begin
      i2d_DHxparams_bio:=ASN1_i2d_bio(@i2d_DHxparams,bp,x);
    end;

    function  DH_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      DH_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH,l,p,newf,dupf,freef);
    end;

    function  EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx:PEVP_PKEY_CTX;len : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_paramgen_prime_len:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DH,EVP_PKEY_OP_PARAMGEN,EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN,len,nil);
    end;

    function  EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx:PEVP_PKEY_CTX;len : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_paramgen_subprime_len:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DH,EVP_PKEY_OP_PARAMGEN,EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN,len,nil);
    end;

    function  EVP_PKEY_CTX_set_dh_paramgen_type(ctx:PEVP_PKEY_CTX;typ : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_paramgen_type:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DH,EVP_PKEY_OP_PARAMGEN,EVP_PKEY_CTRL_DH_PARAMGEN_TYPE,typ,nil);
    end;

    function  EVP_PKEY_CTX_set_dh_paramgen_generator(ctx:PEVP_PKEY_CTX;gen : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_paramgen_generator:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DH,EVP_PKEY_OP_PARAMGEN,EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR,gen,nil);
    end;

    function  EVP_PKEY_CTX_set_dh_rfc5114(ctx:PEVP_PKEY_CTX;gen : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_rfc5114:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_PARAMGEN,EVP_PKEY_CTRL_DH_RFC5114,gen,nil);
    end;

    function  EVP_PKEY_CTX_set_dhx_rfc5114(ctx:PEVP_PKEY_CTX;gen : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dhx_rfc5114:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_PARAMGEN,EVP_PKEY_CTRL_DH_RFC5114,gen,nil);
    end;

    function  EVP_PKEY_CTX_set_dh_kdf_type(ctx:PEVP_PKEY_CTX;kdf : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_kdf_type:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_DH_KDF_TYPE,kdf,nil);
    end;

    function  EVP_PKEY_CTX_get_dh_kdf_type(ctx : PEVP_PKEY_CTX) : cint; inline;
    begin
      EVP_PKEY_CTX_get_dh_kdf_type:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_DH_KDF_TYPE,-(2),nil);
    end;

    function  EVP_PKEY_CTX_set0_dh_kdf_oid(ctx : PEVP_PKEY_CTX;oid : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_set0_dh_kdf_oid:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_DH_KDF_OID,0,oid);
    end;

    function  EVP_PKEY_CTX_get0_dh_kdf_oid(ctx : PEVP_PKEY_CTX;poid : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get0_dh_kdf_oid:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_GET_DH_KDF_OID,0,poid);
    end;

    function  EVP_PKEY_CTX_set_dh_kdf_md(ctx : PEVP_PKEY_CTX;md : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_kdf_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_DH_KDF_MD,0,md);
    end;

    function  EVP_PKEY_CTX_get_dh_kdf_md(ctx : PEVP_PKEY_CTX;pmd : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_dh_kdf_md:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_GET_DH_KDF_MD,0,pmd);
    end;

    function  EVP_PKEY_CTX_set_dh_kdf_outlen(ctx : PEVP_PKEY_CTX;len : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dh_kdf_outlen:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_DH_KDF_OUTLEN,len,nil);
    end;

    function  EVP_PKEY_CTX_get_dh_kdf_outlen(ctx : PEVP_PKEY_CTX;plen : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get_dh_kdf_outlen:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN,0,plen);
    end;

    function  EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx : PEVP_PKEY_CTX;p:Pointer;plen : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set0_dh_kdf_ukm:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_DH_KDF_UKM,plen,p);
    end;

    function  EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx : PEVP_PKEY_CTX;p : Pointer) : cint; inline;
    begin
      EVP_PKEY_CTX_get0_dh_kdf_ukm:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DHX,EVP_PKEY_OP_DERIVE,EVP_PKEY_CTRL_GET_DH_KDF_UKM,0,p);
    end;

    function  d2i_DSAparams_bio(bp:PBIO;x:Ppointer) : Pointer; inline;
    begin
      d2i_DSAparams_bio:=ASN1_d2i_bio(TPfunction(@DSA_new),@d2i_DSAparams,bp,x);
    end;

    function  i2d_DSAparams_bio(bp:PBIO;x:PByte) : cint; inline;
    begin
      i2d_DSAparams_bio:=ASN1_i2d_bio(@i2d_DSAparams,bp,x);
    end;

    function  DSA_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      DSA_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA,l,p,newf,dupf,freef);
    end;

    function  EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx:PEVP_PKEY_CTX; nbits : cint) : cint; inline;
    begin
      EVP_PKEY_CTX_set_dsa_paramgen_bits:=EVP_PKEY_CTX_ctrl(ctx,EVP_PKEY_DSA,EVP_PKEY_OP_PARAMGEN,EVP_PKEY_CTRL_DSA_PARAMGEN_BITS,nbits,nil);
    end;

    function  X509_STORE_CTX_set_app_data(ctx:PX509_STORE_CTX;data : pointer) : cint; inline;
    begin
      X509_STORE_CTX_set_app_data:=X509_STORE_CTX_set_ex_data(ctx,0,data);
    end;

    function  X509_STORE_CTX_get_app_data(ctx : PX509_STORE_CTX) : pointer; inline;
    begin
      X509_STORE_CTX_get_app_data:=X509_STORE_CTX_get_ex_data(ctx,0);
    end;

    function  X509_LOOKUP_load_file(x:PX509_STORE_CTX;name:Pbyte;_type:clong) : cint; inline;
    begin
      X509_LOOKUP_load_file:=X509_LOOKUP_ctrl(x,X509_L_FILE_LOAD,name,_type,nil);
    end;

    function  X509_LOOKUP_add_dir(x:PX509_STORE_CTX;name:Pbyte;_type:clong) : cint; inline;
    begin
      X509_LOOKUP_add_dir:=X509_LOOKUP_ctrl(x,X509_L_ADD_DIR,name,_type,nil);
    end;

    Procedure  X509_STORE_set_verify_func(ctx:PX509_STORE; func : TX509_STORE_CTX_verify_fn); inline;
    begin
      X509_STORE_set_verify(ctx,func);
    end;

    procedure  X509_STORE_set_verify_cb_func(ctx:PX509_STORE;func:TX509_STORE_CTX_verify_cb); inline;
    begin
      X509_STORE_set_verify_cb(ctx,func);
    end;

    procedure  X509_STORE_set_lookup_crls_cb(ctx:PX509_STORE;func:TX509_STORE_CTX_lookup_crls_fn); inline;
    begin
      X509_STORE_set_lookup_crls(ctx,func);
    end;

    function  X509_STORE_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      X509_STORE_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE,l,p,newf,dupf,freef);
    end;

    function  X509_STORE_CTX_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      X509_STORE_CTX_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX,l,p,newf,dupf,freef);
    end;

    function  PKCS7_get_signed_attributes(si : Ppkcs7_signer_info) : PX509_ATTRIBUTE; inline;
    begin
      PKCS7_get_signed_attributes:=si^.auth_attr;
    end;

    function  PKCS7_get_attributes(si : Ppkcs7_signer_info) : PX509_ATTRIBUTE; inline;
    begin
      PKCS7_get_attributes:=si^.unauth_attr;
    end;

    function  PKCS7_type_is_signed(a : Ppkcs7) : Boolean; inline;
    begin
      PKCS7_type_is_signed:=(OBJ_obj2nid(a^._type))=NID_pkcs7_signed;
    end;

    function  PKCS7_type_is_encrypted(a : Ppkcs7) : Boolean; inline;
    begin
      PKCS7_type_is_encrypted:=(OBJ_obj2nid(a^._type))=NID_pkcs7_encrypted;
    end;

    function  PKCS7_type_is_enveloped(a : Ppkcs7) : Boolean; inline;
    begin
      PKCS7_type_is_enveloped:=(OBJ_obj2nid(a^._type))=NID_pkcs7_enveloped;
    end;

    function  PKCS7_type_is_signedAndEnveloped(a : Ppkcs7) : Boolean; inline;
    begin
      PKCS7_type_is_signedAndEnveloped:=(OBJ_obj2nid(a^._type))=NID_pkcs7_signedAndEnveloped;
    end;

    function  PKCS7_type_is_data(a : Ppkcs7) : Boolean; inline;
    begin
      PKCS7_type_is_data:=(OBJ_obj2nid(a^._type))=NID_pkcs7_data;
    end;

    function  PKCS7_type_is_digest(a : Ppkcs7) : Boolean; inline;
    begin
      PKCS7_type_is_digest:=(OBJ_obj2nid(a^._type))=NID_pkcs7_digest;
    end;

    function  PKCS7_set_detached(p:Ppkcs7;v : clong) : clong; inline;
    begin
      PKCS7_set_detached:=PKCS7_ctrl(p,PKCS7_OP_SET_DETACHED_SIGNATURE,v,nil);
    end;

    function  PKCS7_get_detached(p : Ppkcs7) : clong; inline;
    begin
      PKCS7_get_detached:=PKCS7_ctrl(p,PKCS7_OP_GET_DETACHED_SIGNATURE,0,nil);
    end;

    function  PKCS7_is_detached(p7 : Ppkcs7) : Boolean; inline;
    begin
      PKCS7_is_detached:=(PKCS7_type_is_signed(p7)) and (PKCS7_get_detached(p7)<>0);
    end;

    function  X509_extract_key(x : PX509) : PEVP_PKEY; inline;
    begin
      X509_extract_key:=X509_get_pubkey(x);
    end;

    function  X509_REQ_extract_key(a : PX509) : PEVP_PKEY; inline;
    begin
      X509_REQ_extract_key:=X509_REQ_get_pubkey(a);
    end;

    function  X509_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      X509_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509,l,p,newf,dupf,freef);
    end;

    function  SSL_CTX_set_mode(ctx:PSSL_CTX;op : clong) : clong; inline;
    begin
      SSL_CTX_set_mode:=SSL_CTX_ctrl(ctx,SSL_CTRL_MODE,op,nil);
    end;

    function  SSL_CTX_clear_mode(ctx:PSSL_CTX;op : clong) : clong; inline;
    begin
      SSL_CTX_clear_mode:=SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_MODE,op,nil);
    end;

    function  SSL_CTX_get_mode(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_mode:=SSL_CTX_ctrl(ctx,SSL_CTRL_MODE,0,nil);
    end;

    function  SSL_clear_mode(ssl:PSSL;op : clong) : clong; inline;
    begin
      SSL_clear_mode:=SSL_ctrl(ssl,SSL_CTRL_CLEAR_MODE,op,nil);
    end;

    function  SSL_set_mode(ssl:PSSL;op : clong) : clong; inline;
    begin
      SSL_set_mode:=SSL_ctrl(ssl,SSL_CTRL_MODE,op,nil);
    end;

    function  SSL_get_mode(ssl : PSSL) : clong; inline;
    begin
      SSL_get_mode:=SSL_ctrl(ssl,SSL_CTRL_MODE,0,nil);
    end;

    function  SSL_set_mtu(ssl : PSSL;mtu : clong) : clong; inline;
    begin
      SSL_set_mtu:=SSL_ctrl(ssl,SSL_CTRL_SET_MTU,mtu,nil);
    end;

    function  DTLS_set_link_mtu(ssl : PSSL;mtu : clong) : clong; inline;
    begin
      DTLS_set_link_mtu:=SSL_ctrl(ssl,DTLS_CTRL_SET_LINK_MTU,mtu,nil);
    end;

    function  DTLS_get_link_min_mtu(ssl : PSSL) : clong; inline;
    begin
      DTLS_get_link_min_mtu:=SSL_ctrl(ssl,DTLS_CTRL_GET_LINK_MIN_MTU,0,nil);
    end;

    function  SSL_get_secure_renegotiation_support(ssl : PSSL) : clong; inline;
    begin
      SSL_get_secure_renegotiation_support:=SSL_ctrl(ssl,SSL_CTRL_GET_RI_SUPPORT,0,nil);
    end;

    function  SSL_heartbeat(ssl : PSSL) : clong; inline;
    begin
      SSL_heartbeat:=SSL_ctrl(ssl,SSL_CTRL_DTLS_EXT_SEND_HEARTBEAT,0,nil);
    end;

    function  SSL_CTX_set_cert_flags(ctx:PSSL_CTX;op : clong) : clong; inline;
    begin
      SSL_CTX_set_cert_flags:=SSL_CTX_ctrl(ctx,SSL_CTRL_CERT_FLAGS,op,nil);
    end;

    function  SSL_set_cert_flags(s:PSSL;op : clong) : clong; inline;
    begin
      SSL_set_cert_flags:=SSL_ctrl(s,SSL_CTRL_CERT_FLAGS,op,nil);
    end;

    function  SSL_CTX_clear_cert_flags(ctx:PSSL_CTX;op : clong) : clong; inline;
    begin
      SSL_CTX_clear_cert_flags:=SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_CERT_FLAGS,op,nil);
    end;

    function  SSL_clear_cert_flags(s:PSSL;op : clong) : clong; inline;
    begin
      SSL_clear_cert_flags:=SSL_ctrl(s,SSL_CTRL_CLEAR_CERT_FLAGS,op,nil);
    end;

    function  SSL_CTX_set_msg_callback_arg(ctx:PSSL_CTX;arg : Pointer) : clong; inline;
    begin
      SSL_CTX_set_msg_callback_arg:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MSG_CALLBACK_ARG,0,arg);
    end;

    function  SSL_set_msg_callback_arg(ssl:PSSL;arg : Pointer) : clong; inline;
    begin
      SSL_set_msg_callback_arg:=SSL_ctrl(ssl,SSL_CTRL_SET_MSG_CALLBACK_ARG,0,arg);
    end;

    function  SSL_get_extms_support(s : PSSL) : clong; inline;
    begin
      SSL_get_extms_support:=SSL_ctrl(s,SSL_CTRL_GET_EXTMS_SUPPORT,0,nil);
    end;

    function  SSL_CTX_sess_number(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_number:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_NUMBER,0,nil);
    end;

    function  SSL_CTX_sess_connect(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_connect:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT,0,nil);
    end;

    function  SSL_CTX_sess_connect_good(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_connect_good:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_GOOD,0,nil);
    end;

    function  SSL_CTX_sess_connect_renegotiate(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_connect_renegotiate:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_RENEGOTIATE,0,nil);
    end;

    function  SSL_CTX_sess_accept(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_accept:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT,0,nil);
    end;

    function  SSL_CTX_sess_accept_renegotiate(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_accept_renegotiate:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_RENEGOTIATE,0,nil);
    end;

    function  SSL_CTX_sess_accept_good(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_accept_good:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_GOOD,0,nil);
    end;

    function  SSL_CTX_sess_hits(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_hits:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_HIT,0,nil);
    end;

    function  SSL_CTX_sess_cb_hits(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_cb_hits:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CB_HIT,0,nil);
    end;

    function  SSL_CTX_sess_misses(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_misses:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_MISSES,0,nil);
    end;

    function  SSL_CTX_sess_timeouts(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_timeouts:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_TIMEOUTS,0,nil);
    end;

    function  SSL_CTX_sess_cache_full(ctx : PSSL_CTX) : clong;    inline;
    begin
      SSL_CTX_sess_cache_full:=SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CACHE_FULL,0,nil);
    end;

    function  SSL_want_nothing(s : PSSL) : Boolean; inline;
    begin
      SSL_want_nothing:=(SSL_want(s))=SSL_NOTHING;
    end;

    function  SSL_want_read(s : PSSL) : Boolean; inline;
    begin
      SSL_want_read:=(SSL_want(s))=SSL_READING;
    end;

    function  SSL_want_write(s : PSSL) : Boolean; inline;
    begin
      SSL_want_write:=(SSL_want(s))=SSL_WRITING;
    end;

    function  SSL_want_x509_lookup(s : PSSL) : Boolean; inline;
    begin
      SSL_want_x509_lookup:=(SSL_want(s))=SSL_X509_LOOKUP;
    end;

    function  SSL_want_async(s : PSSL) : Boolean; inline;
    begin
      SSL_want_async:=(SSL_want(s))=SSL_ASYNC_PAUSED;
    end;

    function  SSL_want_async_job(s : PSSL) : Boolean; inline;
    begin
      SSL_want_async_job:=(SSL_want(s))=SSL_ASYNC_NO_JOBS;
    end;

    function  TLS1_get_version(s : PSSL) : cint; inline;
    begin
      Result:=SSL_version(s);
    end;

    function  TLS1_get_client_version(s : PSSL) : cint; inline;
    begin
      Result:=SSL_client_version(s);
    end;

    function  SSL_set_tlsext_host_name(s : PSSL;name : Pointer) : clong; inline;
    begin
      SSL_set_tlsext_host_name:=SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,name);
    end;

    function  SSL_set_tlsext_debug_arg(ssl : PSSL;arg : Pointer) : clong; inline;
    begin
      SSL_set_tlsext_debug_arg:=SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_DEBUG_ARG,0,arg);
    end;

    function  SSL_get_tlsext_status_type(ssl : PSSL) : clong; inline;
    begin
      SSL_get_tlsext_status_type:=SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,0,nil);
    end;

    function  SSL_set_tlsext_status_type(ssl : PSSL;_type : clong) : clong; inline;
    begin
      SSL_set_tlsext_status_type:=SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,_type,nil);
    end;

    function  SSL_get_tlsext_status_exts(ssl : PSSL;arg : Pointer) : clong; inline;
    begin
      SSL_get_tlsext_status_exts:=SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS,0,arg);
    end;

    function  SSL_set_tlsext_status_exts(ssl : PSSL;arg : Pointer) : clong; inline;
    begin
      SSL_set_tlsext_status_exts:=SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS,0,arg);
    end;

    function  SSL_get_tlsext_status_ids(ssl : PSSL;arg : Pointer) : clong; inline;
    begin
      SSL_get_tlsext_status_ids:=SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS,0,arg);
    end;

    function  SSL_set_tlsext_status_ids(ssl : PSSL;arg : Pointer) : clong; inline;
    begin
      SSL_set_tlsext_status_ids:=SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS,0,arg);
    end;

    function  SSL_get_tlsext_status_ocsp_resp(ssl : PSSL;arg : Pointer) : clong; inline;
    begin
      SSL_get_tlsext_status_ocsp_resp:=SSL_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP,0,arg);
    end;

    function  SSL_set_tlsext_status_ocsp_resp(ssl : PSSL;arg:Pointer;arglen : clong) : clong; inline;
    begin
      SSL_set_tlsext_status_ocsp_resp:=SSL_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,arglen,arg);
    end;

    function  SSL_CTX_set_tlsext_servername_arg(ctx:PSSL_CTX;arg : Pointer) : clong; inline;
    begin
      SSL_CTX_set_tlsext_servername_arg:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG,0,arg);
    end;

    function  SSL_CTX_get_tlsext_ticket_keys(ctx:PSSL_CTX;keys:Pointer;keylen : clong) : clong; inline;
    begin
      SSL_CTX_get_tlsext_ticket_keys:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_TLSEXT_TICKET_KEYS,keylen,keys);
    end;

    function  SSL_CTX_set_tlsext_ticket_keys(ctx:PSSL_CTX;keys:Pointer;keylen : clong) : clong; inline;
    begin
      SSL_CTX_set_tlsext_ticket_keys:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TLSEXT_TICKET_KEYS,keylen,keys);
    end;

    function  SSL_CTX_get_tlsext_status_arg(ssl:PSSL_CTX;arg : Pointer) : clong; inline;
    begin
      SSL_CTX_get_tlsext_status_arg:=SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG,0,arg);
    end;

    function  SSL_CTX_set_tlsext_status_arg(ssl:PSSL_CTX;arg : Pointer) : clong; inline;
    begin
      SSL_CTX_set_tlsext_status_arg:=SSL_CTX_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG,0,arg);
    end;

    function  SSL_CTX_set_tlsext_status_type(ssl:PSSL_CTX;_type : clong) : clong; inline;
    begin
      SSL_CTX_set_tlsext_status_type:=SSL_CTX_ctrl(ssl,SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE,_type,nil);
    end;

    function  SSL_CTX_get_tlsext_status_type(ssl : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_tlsext_status_type:=SSL_CTX_ctrl(ssl,SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE,0,nil);
    end;

    function  SSL_get_dtlsext_heartbeat_pending(ssl : PSSL) : clong; inline;
    begin
      SSL_get_dtlsext_heartbeat_pending:=SSL_ctrl(ssl,SSL_CTRL_GET_DTLS_EXT_HEARTBEAT_PENDING,0,nil);
    end;

    function  SSL_set_dtlsext_heartbeat_no_requests(ssl:PSSL;arg : clong) : clong; inline;
    begin
      SSL_set_dtlsext_heartbeat_no_requests:=SSL_ctrl(ssl,SSL_CTRL_SET_DTLS_EXT_HEARTBEAT_NO_REQUESTS,arg,nil);
    end;

    function  SSL_get_tlsext_heartbeat_pending(ssl : PSSL) : clong; inline;
    begin
      SSL_get_tlsext_heartbeat_pending:=SSL_get_dtlsext_heartbeat_pending(ssl);
    end;

    function  SSL_set_tlsext_heartbeat_no_requests(ssl:PSSL;arg : clong) : clong;  inline;
    begin
      SSL_set_tlsext_heartbeat_no_requests:=SSL_set_dtlsext_heartbeat_no_requests(ssl,arg);
    end;

    function  SSL_get_app_data(s : PSSL) : Pointer; inline;
    begin
      SSL_get_app_data:=SSL_get_ex_data(s,0);
    end;

    function  SSL_SESSION_set_app_data(s : PSSL_SESSION;a : Pointer) : cint; inline;
    begin
      SSL_SESSION_set_app_data:=SSL_SESSION_set_ex_data(s,0,a);
    end;

    function  SSL_SESSION_get_app_data(s : PSSL_SESSION) : Pointer; inline;
    begin
      SSL_SESSION_get_app_data:=SSL_SESSION_get_ex_data(s,0);
    end;

    function  SSL_CTX_get_app_data(ctx : PSSL_CTX) : Pointer; inline;
    begin
      SSL_CTX_get_app_data:=SSL_CTX_get_ex_data(ctx,0);
    end;

    function  SSL_CTX_set_app_data(ctx : PSSL_CTX;arg : Pointer) : cint; inline;
    begin
      SSL_CTX_set_app_data:=SSL_CTX_set_ex_data(ctx,0,arg);
    end;

    function  SSL_in_connect_init(a : PSSL) : Boolean; inline;
    begin
      SSL_in_connect_init:=(SSL_in_init(a)<>0) and (SSL_is_server(a)=0);
    end;

    function  SSL_in_accept_init(a : PSSL) : Boolean; inline;
    begin
      SSL_in_accept_init:=(SSL_in_init(a)<>0) and (SSL_is_server(a)<>0);
    end;

    function  OpenSSL_add_ssl_algorithms : longint; inline;
    begin
      OpenSSL_add_ssl_algorithms:=SSL_library_init;
    end;

    function  SSLeay_add_ssl_algorithms : longint; inline;
    begin
      SSLeay_add_ssl_algorithms:=SSL_library_init;
    end;

    function  SSL_get_cipher(s : PSSL) : PByte; inline;
    begin
      SSL_get_cipher:=SSL_CIPHER_get_name(SSL_get_current_cipher(s));
    end;

    function  SSL_get_cipher_bits(s : PSSL;np : pcint) : cint; inline;
    begin
      SSL_get_cipher_bits:=SSL_CIPHER_get_bits(SSL_get_current_cipher(s),np);
    end;

    function  SSL_get_cipher_version(s : PSSL) : PByte; inline;
    begin
      SSL_get_cipher_version:=SSL_CIPHER_get_version(SSL_get_current_cipher(s));
    end;

    function  SSL_get_cipher_name(s : PSSL) : PByte; inline;
    begin
      SSL_get_cipher_name:=SSL_CIPHER_get_name(SSL_get_current_cipher(s));
    end;

    function  SSL_get_time(a : PSSL_SESSION) : clong; inline;
    begin
      SSL_get_time:=SSL_SESSION_get_time(a);
    end;

    function  SSL_set_time(a : PSSL_SESSION;b : clong) : clong; inline;
    begin
      SSL_set_time:=SSL_SESSION_set_time(a,b);
    end;

    function  SSL_get_timeout(a : PSSL_SESSION) : clong; inline;
    begin
      SSL_get_timeout:=SSL_SESSION_get_timeout(a);
    end;

    function  SSL_set_timeout(a : PSSL_SESSION;b : clong) : clong; inline;
    begin
      SSL_set_timeout:=SSL_SESSION_set_timeout(a,b);
    end;

    function  d2i_SSL_SESSION_bio(bp:PBIO;s_id : Ppointer) : Pointer; inline;
    begin
      d2i_SSL_SESSION_bio:=ASN1_d2i_bio(TPfunction(@SSL_SESSION_new),@d2i_SSL_SESSION,bp,s_id);
    end;

    function  i2d_SSL_SESSION_bio(bp:PBIO;s_id : PByte) : cint;  inline;
    begin
      i2d_SSL_SESSION_bio:=ASN1_i2d_bio(@i2d_SSL_SESSION,bp,s_id);
    end;

    function  DTLSv1_get_timeout(ssl:PSSL;arg : Pointer) : clong; inline;
    begin
      DTLSv1_get_timeout:=SSL_ctrl(ssl,DTLS_CTRL_GET_TIMEOUT,0,arg);
    end;

    function  DTLSv1_handle_timeout(ssl : PSSL) : clong; inline;
    begin
      DTLSv1_handle_timeout:=SSL_ctrl(ssl,DTLS_CTRL_HANDLE_TIMEOUT,0,nil);
    end;

    function  SSL_num_renegotiations(ssl : PSSL) : clong; inline;
    begin
      SSL_num_renegotiations:=SSL_ctrl(ssl,SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,nil);
    end;

    function  SSL_clear_num_renegotiations(ssl : PSSL) : clong; inline;
    begin
      SSL_clear_num_renegotiations:=SSL_ctrl(ssl,SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,nil);
    end;

    function  SSL_total_renegotiations(ssl : PSSL) : clong; inline;
    begin
      SSL_total_renegotiations:=SSL_ctrl(ssl,SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,nil);
    end;

    function  SSL_CTX_set_tmp_dh(ctx:PSSL_CTX;dh : Pointer) : clong; inline;
    begin
      SSL_CTX_set_tmp_dh:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,dh);
    end;

    function  SSL_CTX_set_tmp_ecdh(ctx:PSSL_CTX;ecdh : Pointer) : clong; inline;
    begin
      SSL_CTX_set_tmp_ecdh:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,ecdh);
    end;

    function  SSL_CTX_set_dh_auto(ctx:PSSL_CTX;onoff : clong) : clong; inline;
    begin
      SSL_CTX_set_dh_auto:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_DH_AUTO,onoff,nil);
    end;

    function  SSL_set_dh_auto(s : PSSL;onoff : clong) : clong; inline;
    begin
      SSL_set_dh_auto:=SSL_ctrl(s,SSL_CTRL_SET_DH_AUTO,onoff,nil);
    end;

    function  SSL_set_tmp_dh(ssl : PSSL;dh : Pointer) : clong; inline;
    begin
      SSL_set_tmp_dh:=SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,dh);
    end;

    function  SSL_set_tmp_ecdh(ssl : PSSL;ecdh : Pointer) : clong; inline;
    begin
      SSL_set_tmp_ecdh:=SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,ecdh);
    end;

    function  SSL_CTX_add_extra_chain_cert(ctx:PSSL_CTX;x509 : Pointer) : clong; inline;
    begin
      SSL_CTX_add_extra_chain_cert:=SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,x509);
    end;

    function  SSL_CTX_get_extra_chain_certs(ctx:PSSL_CTX;px509 : Pointer) : clong; inline;
    begin
      SSL_CTX_get_extra_chain_certs:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509);
    end;

    function  SSL_CTX_get_extra_chain_certs_only(ctx:PSSL_CTX;px509 : Pointer) : clong; inline;
    begin
      SSL_CTX_get_extra_chain_certs_only:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509);
    end;

    function  SSL_CTX_clear_extra_chain_certs(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_clear_extra_chain_certs:=SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,nil);
    end;

    function  SSL_CTX_set0_chain(ctx : PSSL_CTX;sk : Pointer) : clong; inline;
    begin
      SSL_CTX_set0_chain:=SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,sk);
    end;

    function  SSL_CTX_set1_chain(ctx : PSSL_CTX;sk : Pointer) : clong; inline;
    begin
      SSL_CTX_set1_chain:=SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,sk);
    end;

    function  SSL_CTX_add0_chain_cert(ctx:PSSL_CTX;x509 : Pointer) : clong; inline;
    begin
      SSL_CTX_add0_chain_cert:=SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,x509);
    end;

    function  SSL_CTX_add1_chain_cert(ctx:PSSL_CTX;x509 : Pointer) : clong; inline;
    begin
      SSL_CTX_add1_chain_cert:=SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,x509);
    end;

    function  SSL_CTX_get0_chain_certs(ctx:PSSL_CTX;px509 : Pointer) : clong; inline;
    begin
      SSL_CTX_get0_chain_certs:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509);
    end;

    function  SSL_CTX_clear_chain_certs(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_clear_chain_certs:=SSL_CTX_set0_chain(ctx,nil);
    end;

    function  SSL_CTX_build_cert_chain(ctx:PSSL_CTX;flags : clong) : clong; inline;
    begin
      SSL_CTX_build_cert_chain:=SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN,flags,nil);
    end;

    function  SSL_CTX_select_current_cert(ctx:PSSL_CTX;x509 : Pointer) : clong;  inline;
    begin
      SSL_CTX_select_current_cert:=SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,x509);
    end;

    function  SSL_CTX_set_current_cert(ctx:PSSL_CTX;op : clong) : clong; inline;
    begin
      SSL_CTX_set_current_cert:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT,op,nil);
    end;

    function  SSL_CTX_set0_verify_cert_store(ctx:PSSL_CTX;st : Pointer) : clong; inline;
    begin
      SSL_CTX_set0_verify_cert_store:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,st);
    end;

    function  SSL_CTX_set1_verify_cert_store(ctx:PSSL_CTX;st : Pointer) : clong; inline;
    begin
      SSL_CTX_set1_verify_cert_store:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,st);
    end;

    function  SSL_CTX_set0_chain_cert_store(ctx:PSSL_CTX;st : Pointer) : clong; inline;
    begin
      SSL_CTX_set0_chain_cert_store:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,st);
    end;

    function  SSL_CTX_set1_chain_cert_store(ctx:PSSL_CTX;st : Pointer) : clong; inline;
    begin
      SSL_CTX_set1_chain_cert_store:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,st);
    end;

    function  SSL_set0_chain(ctx:PSSL;sk : Pointer) : clong; inline;
    begin
      SSL_set0_chain:=SSL_ctrl(ctx,SSL_CTRL_CHAIN,0,sk);
    end;

    function  SSL_set1_chain(ctx:PSSL;sk : Pointer) : clong; inline;
    begin
      SSL_set1_chain:=SSL_ctrl(ctx,SSL_CTRL_CHAIN,1,sk);
    end;

    function  SSL_add0_chain_cert(ctx:PSSL;x509 : Pointer) : clong; inline;
    begin
      SSL_add0_chain_cert:=SSL_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,x509);
    end;

    function  SSL_add1_chain_cert(ctx:PSSL;x509 : Pointer) : longint; inline;
    begin
      SSL_add1_chain_cert:=SSL_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,x509);
    end;

    function  SSL_get0_chain_certs(ctx:PSSL;px509 : Pointer) : clong; inline;
    begin
      SSL_get0_chain_certs:=SSL_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509);
    end;

    function  SSL_clear_chain_certs(ctx : PSSL) : clong; inline;
    begin
      SSL_clear_chain_certs:=SSL_set0_chain(ctx,nil);
    end;

    function  SSL_build_cert_chain(s : PSSL;flags : clong) : clong; inline;
    begin
      SSL_build_cert_chain:=SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN,flags,nil);
    end;

    function  SSL_select_current_cert(ctx:PSSL;x509 : Pointer) : clong; inline;
    begin
      SSL_select_current_cert:=SSL_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,x509);
    end;

    function  SSL_set_current_cert(ctx:PSSL;op : clong) : clong; inline;
    begin
      SSL_set_current_cert:=SSL_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT,op,nil);
    end;

    function  SSL_set0_verify_cert_store(s:PSSL;st : Pointer) : clong; inline;
    begin
      SSL_set0_verify_cert_store:=SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,st);
    end;

    function  SSL_set1_verify_cert_store(s:PSSL;st : Pointer) : clong; inline;
    begin
      SSL_set1_verify_cert_store:=SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,st);
    end;

    function  SSL_set0_chain_cert_store(s:PSSL;st : Pointer) : clong; inline;
    begin
      SSL_set0_chain_cert_store:=SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,st);
    end;

    function  SSL_set1_chain_cert_store(s:PSSL;st : Pointer) : clong; inline;
    begin
      SSL_set1_chain_cert_store:=SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,st);
    end;

    function  SSL_get1_curves(ctx:PSSL;s : Pointer) : clong; inline;
    begin
      SSL_get1_curves:=SSL_ctrl(ctx,SSL_CTRL_GET_CURVES,0,s);
    end;

    function  SSL_CTX_set1_curves(ctx:PSSL_CTX;clist:Pointer;clistlen : clong) : clong; inline;
    begin
      SSL_CTX_set1_curves:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURVES,clistlen,clist);
    end;

    function  SSL_CTX_set1_curves_list(ctx:PSSL_CTX;s : Pointer) : clong; inline;
    begin
      SSL_CTX_set1_curves_list:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURVES_LIST,0,s);
    end;

    function  SSL_set1_curves(ctx:PSSL;clist:Pointer;clistlen : clong) : clong; inline;
    begin
      SSL_set1_curves:=SSL_ctrl(ctx,SSL_CTRL_SET_CURVES,clistlen,clist);
    end;

    function  SSL_set1_curves_list(ctx:PSSL;s : Pointer) : clong; inline;
    begin
      SSL_set1_curves_list:=SSL_ctrl(ctx,SSL_CTRL_SET_CURVES_LIST,0,s);
    end;

    function  SSL_get_shared_curve(s:PSSL;n : clong) : clong; inline;
    begin
      SSL_get_shared_curve:=SSL_ctrl(s,SSL_CTRL_GET_SHARED_CURVE,n,nil);
    end;

    function  SSL_CTX_set1_sigalgs(ctx:PSSL_CTX;slist:Pointer;slistlen : clong) : clong; inline;
    begin
      SSL_CTX_set1_sigalgs:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,slist);
    end;

    function  SSL_CTX_set1_sigalgs_list(ctx:PSSL_CTX;s : Pointer) : clong; inline;
    begin
      SSL_CTX_set1_sigalgs_list:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,s);
    end;

    function  SSL_set1_sigalgs(ctx:PSSL;slist:Pointer;slistlen : clong) : clong; inline;
    begin
      SSL_set1_sigalgs:=SSL_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,slist);
    end;

    function  SSL_set1_sigalgs_list(ctx:PSSL;s : Pointer) : clong; inline;
    begin
      SSL_set1_sigalgs_list:=SSL_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,s);
    end;

    function  SSL_CTX_set1_client_sigalgs(ctx:PSSL_CTX;slist:Pointer;slistlen : clong) : clong; inline;
    begin
      SSL_CTX_set1_client_sigalgs:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,slist);
    end;

    function  SSL_CTX_set1_client_sigalgs_list(ctx:PSSL_CTX;s : Pointer) : clong; inline;
    begin
      SSL_CTX_set1_client_sigalgs_list:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,s);
    end;

    function  SSL_set1_client_sigalgs(ctx:PSSL;slist:Pointer;slistlen : clong) : clong; inline;
    begin
      SSL_set1_client_sigalgs:=SSL_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,slist);
    end;

    function  SSL_set1_client_sigalgs_list(ctx:PSSL;s : Pointer) : clong; inline;
    begin
      SSL_set1_client_sigalgs_list:=SSL_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,s);
    end;

    function  SSL_get0_certificate_types(s:PSSL;clist : Pointer) : clong; inline;
    begin
      SSL_get0_certificate_types:=SSL_ctrl(s,SSL_CTRL_GET_CLIENT_CERT_TYPES,0,clist);
    end;

    function  SSL_CTX_set1_client_certificate_types(ctx:PSSL_CTX;clist:Pointer;clistlen : clong) : clong; inline;
    begin
      SSL_CTX_set1_client_certificate_types:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,clist);
    end;

    function  SSL_set1_client_certificate_types(s:PSSL;clist:Pointer;clistlen : clong) : clong; inline;
    begin
      SSL_set1_client_certificate_types:=SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,clist);
    end;

    function  SSL_get_peer_signature_nid(s:PSSL;pn : Pointer) : clong; inline;
    begin
      SSL_get_peer_signature_nid:=SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn);
    end;

    function  SSL_get_server_tmp_key(s:PSSL;pk : Pointer) : clong; inline;
    begin
      SSL_get_server_tmp_key:=SSL_ctrl(s,SSL_CTRL_GET_SERVER_TMP_KEY,0,pk);
    end;

    function  SSL_get0_raw_cipherlist(s:PSSL;plst : Pointer) : clong; inline;
    begin
      SSL_get0_raw_cipherlist:=SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,plst);
    end;

    function  SSL_get0_ec_point_formats(s:PSSL;plst : Pointer) : clong; inline;
    begin
      SSL_get0_ec_point_formats:=SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,plst);
    end;

    function  SSL_CTX_set_min_proto_version(ctx:PSSL_CTX;version : clong) : clong; inline;
    begin
      SSL_CTX_set_min_proto_version:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MIN_PROTO_VERSION,version,nil);
    end;

    function  SSL_CTX_set_max_proto_version(ctx:PSSL_CTX;version : clong) : clong; inline;
    begin
      SSL_CTX_set_max_proto_version:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_PROTO_VERSION,version,nil);
    end;

    function  SSL_CTX_get_min_proto_version(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_min_proto_version:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_MIN_PROTO_VERSION,0,nil);
    end;

    function  SSL_CTX_get_max_proto_version(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_max_proto_version:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_MAX_PROTO_VERSION,0,nil);
    end;

    function  SSL_set_min_proto_version(s:PSSL;version : clong) : clong; inline;
    begin
      SSL_set_min_proto_version:=SSL_ctrl(s,SSL_CTRL_SET_MIN_PROTO_VERSION,version,nil);
    end;

    function  SSL_set_max_proto_version(s:PSSL;version : clong) : clong; inline;
    begin
      SSL_set_max_proto_version:=SSL_ctrl(s,SSL_CTRL_SET_MAX_PROTO_VERSION,version,nil);
    end;

    function  SSL_get_min_proto_version(s : PSSL) : clong; inline;
    begin
      SSL_get_min_proto_version:=SSL_ctrl(s,SSL_CTRL_GET_MIN_PROTO_VERSION,0,nil);
    end;

    function  SSL_get_max_proto_version(s : PSSL) : clong;
    begin
      SSL_get_max_proto_version:=SSL_ctrl(s,SSL_CTRL_GET_MAX_PROTO_VERSION,0,nil);
    end;

    function  SSL_load_error_strings : cint; inline;
    begin
      SSL_load_error_strings:=OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS,nil);
    end;

    function  SSL_library_init : cint; inline;
    begin
      SSL_library_init:=OPENSSL_init_ssl(0,nil);
    end;

    function  SSL_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      SSL_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL,l,p,newf,dupf,freef);
    end;

    function  SSL_SESSION_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      SSL_SESSION_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_SESSION,l,p,newf,dupf,freef);
    end;

    function  SSL_CTX_get_ex_new_index(l:clong;p:pointer;newf:TCRYPTO_EX_new;dupf:TCRYPTO_EX_dup;freef:TCRYPTO_EX_free):cint; inline;
    begin
      SSL_CTX_get_ex_new_index:=CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX,l,p,newf,dupf,freef);
    end;

    function  SSL_CTX_sess_set_cache_size(ctx:PSSL_CTX;t : clong) : clong; inline;
    begin
      SSL_CTX_sess_set_cache_size:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,nil);
    end;

    function  SSL_CTX_sess_get_cache_size(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_sess_get_cache_size:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,nil);
    end;

    function  SSL_CTX_set_session_cache_mode(ctx:PSSL_CTX;m : clong) : clong; inline;
    begin
      SSL_CTX_set_session_cache_mode:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,nil);
    end;

    function  SSL_CTX_get_session_cache_mode(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_session_cache_mode:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,nil);
    end;

    function  SSL_CTX_get_default_read_ahead(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_default_read_ahead:=SSL_CTX_get_read_ahead(ctx);
    end;

    function  SSL_CTX_set_default_read_ahead(ctx:PSSL_CTX;m : clong) : clong; inline;
    begin
      SSL_CTX_set_default_read_ahead:=SSL_CTX_set_read_ahead(ctx,m);
    end;

    function  SSL_CTX_get_read_ahead(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_read_ahead:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_READ_AHEAD,0,nil);
    end;

    function  SSL_CTX_set_read_ahead(ctx:PSSL_CTX;m : clong) : clong; inline;
    begin
      SSL_CTX_set_read_ahead:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_READ_AHEAD,m,nil);
    end;

    function  SSL_CTX_get_max_cert_list(ctx : PSSL_CTX) : clong; inline;
    begin
      SSL_CTX_get_max_cert_list:=SSL_CTX_ctrl(ctx,SSL_CTRL_GET_MAX_CERT_LIST,0,nil);
    end;

    function  SSL_CTX_set_max_cert_list(ctx:PSSL_CTX;m : clong) : clong; inline;
    begin
      SSL_CTX_set_max_cert_list:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_CERT_LIST,m,nil);
    end;

    function  SSL_get_max_cert_list(ssl : PSSL) : clong; inline;
    begin
      SSL_get_max_cert_list:=SSL_ctrl(ssl,SSL_CTRL_GET_MAX_CERT_LIST,0,nil);
    end;

    function  SSL_set_max_cert_list(ssl:PSSL;m : clong) : clong; inline;
    begin
      SSL_set_max_cert_list:=SSL_ctrl(ssl,SSL_CTRL_SET_MAX_CERT_LIST,m,nil);
    end;

    function  SSL_CTX_set_max_send_fragment(ctx:PSSL_CTX;m : clong) : clong; inline;
    begin
      SSL_CTX_set_max_send_fragment:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,nil);
    end;

    function  SSL_set_max_send_fragment(ssl:PSSL;m : clong) : clong; inline;
    begin
      SSL_set_max_send_fragment:=SSL_ctrl(ssl,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,nil);
    end;

    function  SSL_CTX_set_split_send_fragment(ctx:PSSL_CTX;m : clong) : clong; inline;
    begin
      SSL_CTX_set_split_send_fragment:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,m,nil);
    end;

    function  SSL_set_split_send_fragment(ssl:PSSL;m : clong) : clong; inline;
    begin
      SSL_set_split_send_fragment:=SSL_ctrl(ssl,SSL_CTRL_SET_SPLIT_SEND_FRAGMENT,m,nil);
    end;

    function  SSL_CTX_set_max_pipelines(ctx:PSSL_CTX;m : clong) : clong; inline;
    begin
      SSL_CTX_set_max_pipelines:=SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_PIPELINES,m,nil);
    end;

    function  SSL_set_max_pipelines(ssl:PSSL;m : clong) : clong; inline;
    begin
      SSL_set_max_pipelines:=SSL_ctrl(ssl,SSL_CTRL_SET_MAX_PIPELINES,m,nil);
    end;

    function  SSL_cache_hit(s:PSSL):cint inline;
    begin
      SSL_cache_hit:=SSL_session_reused(s);
    end;

    function  SSL_disable_ct(s : PSSL) : cint; inline;
    begin
      SSL_disable_ct:=SSL_set_ct_validation_callback(s,nil,nil);
    end;

    function  SSL_CTX_disable_ct(ctx : PSSL_CTX) : cint; inline;
    begin
      SSL_CTX_disable_ct:=SSL_CTX_set_ct_validation_callback(ctx,nil,nil);
    end;

    Procedure  SYSerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_SYS,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  BNerr(f,r : cint); inline;
    begin
     ERR_PUT_error(ERR_LIB_BN,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  RSAerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_RSA,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  DHerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_DH,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  EVPerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_EVP,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  BUFerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_BUF,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  OBJerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_OBJ,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  PEMerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_PEM,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  DSAerr(f,r : cint); inline;
    begin
     ERR_PUT_error(ERR_LIB_DSA,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  X509err(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_X509,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  ASN1err(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_ASN1,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  CONFerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_CONF,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  CRYPTOerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_CRYPTO,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  ECerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_EC,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  SSLerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_SSL,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  BIOerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_BIO,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  PKCS7err(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_PKCS7,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  X509V3err(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_X509V3,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  PKCS12err(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_PKCS12,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  RANDerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_RAND,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  DSOerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_DSO,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  ENGINEerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_ENGINE,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  OCSPerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_OCSP,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  UIerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_UI,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  COMPerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_COMP,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  ECDSAerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_ECDSA,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  ECDHerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_ECDH,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  STOREerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_STORE,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  FIPSerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_FIPS,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  CMSerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_CMS,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  TSerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_TS,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  HMACerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_HMAC,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  CTerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_CT,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  ASYNCerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_ASYNC,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    Procedure  KDFerr(f,r : cint); inline;
    begin
      ERR_PUT_error(ERR_LIB_KDF,f,r,OPENSSL_FILE,OPENSSL_LINE);
    end;

    function  ERR_GET_LIB(l : cint) : cint; inline;
    begin
      ERR_GET_LIB:=(l shr 24) and $0FF;
    end;

    function  ERR_GET_FUNC(l : cint) : cint; inline;
    begin
      ERR_GET_FUNC:=(l shr 12) and $FFF;
    end;

    function  ERR_load_crypto_strings : longint; inline;
    begin
      ERR_load_crypto_strings:=OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS,nil);
    end;

    function  NCONF_get_number(c:PCONF;g:pbyte;n:pbyte;r:pclong):cint; inline;
    begin
      NCONF_get_number:=NCONF_get_number_e(c,g,n,r);
    end;

function  SSLv23_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSLv23_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  SSLv23_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSLv23_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  SSLv23_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSLv23_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  SSLv3_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSLv3_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  SSLv3_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSLv3_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  SSLv3_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSLv3_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;


function  TLS_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLS_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLS_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLS_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLS_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLS_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;


function  TLSv1_1_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_1_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLSv1_1_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_1_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLSv1_1_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_1_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;


function  TLSv1_2_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_2_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLSv1_2_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_2_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLSv1_2_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_2_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;


function  TLSv1_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLSv1_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  TLSv1_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'TLSv1_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;


function  DTLS_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLS_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  DTLS_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLS_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  DTLS_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLS_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;


function  DTLSv1_2_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLSv1_2_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  DTLSv1_2_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLSv1_2_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  DTLSv1_2_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLSv1_2_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;


function  DTLSv1_server_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLSv1_server_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  DTLSv1_client_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLSv1_client_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

function  DTLSv1_method:PSSL_METHOD;cdecl;
Var
 M:TSslMethod;
begin
 Result:=nil;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'DTLSv1_method');
 if Assigned(M) then
 begin
  Result:=M();
 end;
end;

type
 TSSL_set_next_protos_cb=Procedure(s,cb,arg:pointer);cdecl;
 TSSL_select_next_proto=function(_out:Ppbyte;outlen:pbyte;_in:pbyte;inlen:cuint;client:pbyte;client_len:cuint):cint;cdecl;
 TSSL_set_alpn_protos=function(ssl,protos:pointer;protos_len:cuint):cint;cdecl;

procedure SSL_CTX_set_next_protos_advertised_cb(s:PSSL_CTX; cb:Tnext_proto_advertised_cb; arg:pointer);cdecl;
Var
 M:TSSL_set_next_protos_cb;
begin
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_CTX_set_next_protos_advertised_cb');
 if Assigned(M) then
 begin
  M(s,cb,arg);
 end;
end;

procedure SSL_CTX_set_next_proto_select_cb(s:PSSL_CTX; cb:Tnext_proto_select_cb; arg:pointer);cdecl;
Var
 M:TSSL_set_next_protos_cb;
begin
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_CTX_set_next_proto_select_cb');
 if Assigned(M) then
 begin
  M(s,cb,arg);
 end;
end;

procedure SSL_get0_next_proto_negotiated(s:PSSL; data:Ppbyte; len:pcunsigned);cdecl;
Var
 M:TSSL_set_next_protos_cb;
begin
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_get0_next_proto_negotiated');
 if Assigned(M) then
 begin
  M(s,data,len);
 end;
end;

function  SSL_select_next_proto(_out:Ppbyte; outlen:pbyte;_in:pbyte; inlen:cuint; client:pbyte; client_len:cuint):cint;cdecl;
Var
 M:TSSL_select_next_proto;
begin
 Result:=0;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_select_next_proto');
 if Assigned(M) then
 begin
  Result:=M(_out,outlen,_in,inlen,client,client_len);
 end;
end;

function  SSL_CTX_set_alpn_protos(ctx:PSSL_CTX; protos:pbyte; protos_len:cuint):cint;cdecl;
Var
 M:TSSL_set_alpn_protos;
begin
 Result:=0;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_CTX_set_alpn_protos');
 if Assigned(M) then
 begin
  Result:=M(ctx,protos,protos_len);
 end;
end;

function  SSL_set_alpn_protos(ssl:PSSL; protos:pbyte; protos_len:cuint):cint;cdecl;
Var
 M:TSSL_set_alpn_protos;
begin
 Result:=0;
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_set_alpn_protos');
 if Assigned(M) then
 begin
  Result:=M(ssl,protos,protos_len);
 end;
end;

procedure SSL_CTX_set_alpn_select_cb(ctx:PSSL_CTX; cb:Tnext_proto_select_cb; arg:pointer);cdecl;
Var
 M:TSSL_set_next_protos_cb;
begin
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_CTX_set_alpn_select_cb');
 if Assigned(M) then
 begin
  M(ctx,cb,arg);
 end;
end;

procedure SSL_get0_alpn_selected(ssl:PSSL; data:Ppbyte; len:pcuint);cdecl;
Var
 M:TSSL_set_next_protos_cb;
begin
 Pointer(M):=GetProcedureAddress(LoadLibrary(DLLSSLName),'SSL_get0_alpn_selected');
 if Assigned(M) then
 begin
  M(ssl,data,len);
 end;
end;

end.
