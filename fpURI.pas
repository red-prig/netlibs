{ URI parser

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

unit fpURI;

{$mode objfpc}{$H+}

interface

type
 TURI=object
  private
   type
    TURIPart=packed record
     P,L:SizeUint;
    end;
   var
    FURI:RawByteString;
    FProtocol,
    FUsername,
    FPassword,
    FHost,
    FPort,
    FPath,
    FQuery,
    FRef:TURIPart;
  public
   function toString():RawByteString; inline;
   function getProtocol():RawByteString;
   function getScheme():RawByteString; inline;
   function getSchemeSpecificPart(Raw:Boolean=false):RawByteString;
   function getUserInfo(Raw:Boolean=false):RawByteString;
   function getUsername(Raw:Boolean=false):RawByteString;
   function getPassword(Raw:Boolean=false):RawByteString;
   function getAuthority(Raw:Boolean=false):RawByteString;
   function getHost():RawByteString;
   function getPort():Word; inline;
   function getPath(Raw:Boolean=false):RawByteString; inline;
   function getQuery(Raw:Boolean=false):RawByteString;
   function getRef(Raw:Boolean=false):RawByteString;
   function getFragment(Raw:Boolean=false):RawByteString; inline;
   function _get(i:Byte):RawByteString;
 end;

function parse_uri(const f:RawByteString;strict:Boolean=false):TURI;
function parse_uri(P:PAnsiChar;Len:SizeUInt;strict:Boolean=false):TURI;

function Unescape(P:PAnsiChar;Len:SizeUInt):RawByteString;
function Unescape(Const S:RawByteString):RawByteString; inline;
function Escape(P:PAnsiChar;Len:SizeUInt):RawByteString;
function Escape(Const S:RawByteString):RawByteString; inline;

implementation

function TryPcharToWord(P:PAnsiChar;Len:SizeUInt;Var Q:Word):Boolean;
Var
 R,T:Word;
 b:Byte;
begin
 Result:=false;

 if (P=nil) then Exit;

 While (Len<>0) and (P[Len-1]<=' ') do
 begin
  Dec(Len);
 end;

 while (Len<>0) and (P^<=' ') do
 begin
  Dec(Len);
  Inc(P);
 end;

 if (Len=0) or (Len>5) then Exit;

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
 Result:=true;
end;

const
 ValidPathChars=['A'..'Z','a'..'z','0'..'9','-','.','_','~','!','$','&','''','(',')','*','+',',',';','=','@',':','/'];
 //ValidQueryChars=['A'..'Z','a'..'z','0'..'9','-','.','_','~','!','$','&','''','(',')','*',',',';','=','@',':','/'];

function Escape(P:PAnsiChar;Len:SizeUInt):RawByteString;
Const
 HexChars:PAnsiChar='0123456789ABCDEF';
var
 i:SizeUInt;
 R:PChar;
 c:AnsiChar;
begin
 Result:='';
 If (P=nil) or (Len=0) then Exit;
 SetLength(Result,Len*3);
 R:=Pchar(Result);
 for I:=0 to Len-1 do
 begin
  C:=P[i];
  if not (c in ValidPathChars) then
  begin
   R^:='%';
   Inc(R);
   R^:=HexChars[Ord(c) shr 4];
   Inc(R);
   R^:=HexChars[Ord(c) and $F];
   Inc(R);
  end
  else
  begin
   R^:=c;
   Inc(R);
  end;
 end;
 SetLength(Result,R-PChar(Result));
 SetCodePage(Result,CP_UTF8,False);
end;

function Escape(Const S:RawByteString):RawByteString; inline;
begin
 Result:=Escape(PAnsiChar(S),Length(S));
end;

function TryHexValue(c:AnsiChar;var b:Byte):Boolean; inline;
Const
 DifLo=Byte('a')-$A;
 DifHi=Byte('A')-$A;
begin
 Result:=true;
 case c of
  '0'..'9':b:=(Byte(c) and $F);
  'a'..'f':b:=(Byte(c)-DifLo);
  'A'..'F':b:=(Byte(c)-DifHi);
 else
  Result:=false;
 end;
end;

function Unescape(P:PAnsiChar;Len:SizeUInt):RawByteString;
var
 R:PAnsiChar;
 i:SizeUInt;
 b1,b2:Byte;
begin
 Result:='';
 if (P=nil) then Exit;
 if Len=0 then Exit;
 SetLength(Result,Len);
 R:=@Result[1];
 i:=0;
 While (I<Len) do
 begin
  Case P[i] of
   '%':if (i+2<Len) and TryHexValue(P[i+1],b1) and TryHexValue(P[i+2],b2) then
       begin
        R^:=AnsiChar((b1 shl 4) or b2);
        Inc(R);
        Inc(I,2);
       end else
       begin
        R^:=P[i];
        Inc(R);
       end;
   else
    begin
     R^:=P[i];
     Inc(R);
    end;
  end;
  Inc(i);
 end;
 SetLength(Result,R-PAnsiChar(Result));
 SetCodePage(Result,CP_UTF8,False);
end;

function Unescape(Const S:RawByteString):RawByteString; inline;
begin
 Result:=Unescape(PAnsiChar(S),Length(S));
end;

function Unescape_trim(P:PAnsiChar;Len:SizeUInt):RawByteString;
begin
 Result:='';
 if (P=nil) then Exit;

 While (Len<>0) and (P[Len-1]<=' ') do
 begin
  Dec(Len);
 end;

 while (Len<>0) and (P^<=' ') do
 begin
  Dec(Len);
  Inc(P);
 end;

 Result:=Unescape(P,Len);
end;

function UnescapeQuery(P:PAnsiChar;Len:SizeUInt):RawByteString;
var
 R:PAnsiChar;
 i:SizeUInt;
 b1,b2:Byte;
begin
 Result:='';
 if (P=nil) then Exit;

 While (Len<>0) and (P[Len-1]<=' ') do
 begin
  Dec(Len);
 end;

 while (Len<>0) and (P^<=' ') do
 begin
  Dec(Len);
  Inc(P);
 end;

 if Len=0 then Exit;
 SetLength(Result,Len);
 R:=@Result[1];
 i:=0;
 While (I<Len) do
 begin
  Case P[i] of
   '%':if (i+2<Len) and TryHexValue(P[i+1],b1) and TryHexValue(P[i+2],b2) then
       begin
        R^:=AnsiChar((b1 shl 4) or b2);
        Inc(R);
        Inc(I,2);
       end else
       begin
        R^:=P[i];
        Inc(R);
       end;
   '+':begin
        R^:=' ';
        Inc(R);
       end;
   else
    begin
     R^:=P[i];
     Inc(R);
    end;
  end;
  Inc(i);
 end;
 SetLength(Result,R-PAnsiChar(Result));
end;

function parse_uri(P:PAnsiChar;Len:SizeUInt;strict:Boolean=false):TURI;
var
 f:RawByteString;
begin
 SetString(f,P,Len);
 Result:=parse_uri(f,strict);
end;

function parse_uri(const f:RawByteString;strict:Boolean=false):TURI;
var
 i,state:SizeUint;
 r1,r2:SizeUInt;

 function IsNotNumber(P,L:SizeUInt):Boolean; inline;
 Var
  Q:Word;
 begin
  Q:=0;
  Result:=not TryPcharToWord(@f[P],L,Q);
 end;

begin
 Result:=Default(TURI);
 Result.FURI:=f;
 r1:=1;
 r2:=1;
 state:=0;
 if Length(f)<>0 then
 With Result do
 begin
  For i:=1 to Length(f) do
   case state of
    0:case f[i] of
       '/':state:=8;
       '?':begin
            state:=9;
            r1:=i+1;
           end;
       '#':begin
            state:=10;
            r1:=i+1;
           end;
       ':':state:=2;
       else
           state:=1;
      end;
    1:case f[i] of
       '/':begin
            state:=8;
            FHost.P:=r1;
            FHost.L:=i-r1;
            r1:=i;
           end;
       ':':begin
            state:=2;
            r2:=i;
           end;
       '@':if not strict then
           begin
            state:=6;
            FUsername.P:=r1;
            FUsername.L:=i-r1;
            r1:=i+1;
           end;
      end;
    2:case f[i] of
       '/':begin
            state:=3;
            FProtocol.P:=r1;
            FProtocol.L:=r2-r1;
            r1:=i+1;
            r2:=r1;
           end;
       else
           if strict then
           begin
            state:=8;
            FProtocol.P:=r1;
            FProtocol.L:=i-r1-1;
            r1:=i;
           end else
            state:=5;
      end;
    3:begin
       state:=4;
       case f[i] of
        '/':r1:=i+1;
        else
         if strict then
         begin
          state:=8;
          r1:=i-1;
         end else
          r1:=i;
       end;
      end;
    4:case f[i] of
       '/':begin
            state:=8;
            FHost.P:=r1;
            FHost.L:=i-r1;
            r1:=i;
           end;
       ':':begin
            state:=5;
            r2:=i;
           end;
       '@':begin
            state:=6;
            FUsername.P:=r1;
            FUsername.L:=i-r1;
            r1:=i+1;
           end;
      end;
    5:case f[i] of
       '/':if IsNotNumber(r2+1,i-r2-1) then
           begin
            state:=8;
            FUsername.P:=r1;
            FUsername.L:=r2-r1;
            FPassword.P:=r2+1;
            FPassword.L:=i-r2-1;
            r1:=i;
           end else
           begin
            state:=8;
            FHost.P:=r1;
            FHost.L:=r2-r1;
            FPort.P:=r2+1;
            FPort.L:=i-r2-1;
            r1:=i;
           end;
       '@':begin
            state:=6;
            FUsername.P:=r1;
            FUsername.L:=r2-r1;
            FPassword.P:=r2+1;
            FPassword.L:=i-r2-1;
            r1:=i+1;
            r2:=r1;
           end;
      end;
    6:case f[i] of
       '/':begin
            state:=8;
            FHost.P:=r1;
            FHost.L:=i-r1;
            r1:=i;
           end;
       ':':begin
            state:=7;
            FHost.P:=r1;
            FHost.L:=i-r1;
            r1:=i+1;
           end;
      end;
    7:case f[i] of
       '/':begin
            state:=8;
            FPort.P:=r1;
            FPort.L:=i-r1;
            r1:=i;
           end;
      end;
    8:case f[i] of
       '?':begin
            state:=9;
            FPath.P:=r1;
            FPath.L:=i-r1;
            r1:=i+1;
           end;
       '#':begin
            state:=10;
            FPath.P:=r1;
            FPath.L:=i-r1;
            r1:=i+1;
           end;
      end;
    9:case f[i] of
       '#':begin
            state:=10;
            FQuery.P:=r1;
            FQuery.L:=i-r1;
            r1:=i+1;
           end;
      end;
   end;

  i:=Length(f)+1;
  case state of
    1:if strict then
      begin
       FProtocol.P:=r1;
       FProtocol.L:=i-r1;
      end else
      begin
       FHost.P:=r1;
       FHost.L:=i-r1;
      end;
    2:begin
       FProtocol.P:=r1;
       FProtocol.L:=r2-r1;
      end;
    3:if strict then
      begin
       FPath.P:=r1-1;
       FPath.L:=i-r1+1;
      end;
    4:begin
       FHost.P:=r1;
       FHost.L:=i-r1;
      end;
    5:if IsNotNumber(r2+1,i-r2-1) then
      begin
       FUsername.P:=r1;
       FUsername.L:=r2-r1;
       FPassword.P:=r2+1;
       FPassword.L:=i-r2-1;
      end else
      begin
       FHost.P:=r1;
       FHost.L:=r2-r1;
       FPort.P:=r2+1;
       FPort.L:=i-r2-1;
      end;
    6:begin
       FHost.P:=r1;
       FHost.L:=i-r1;
      end;
    7:begin
       FPort.P:=r1;
       FPort.L:=i-r1;
      end;
    8:begin
       FPath.P:=r1;
       FPath.L:=i-r1;
      end;
    9:begin
       FQuery.P:=r1;
       FQuery.L:=i-r1;
      end;
   10:begin
       FRef.P:=r1;
       FRef.L:=i-r1;
      end;
  end;

 end;
end;

{
 0 - init
 1 - proto or user or host
 2 - : proto or user or host:port
 3 - / proto
 4 - user or host
 5 - pass or port
 6 - host
 7 - port
 8 - path
 9 - params
10 - bookmark
}

// protocol://user:password@host:port/path/document?arg1=val1&arg2=val2#part

//[scheme:][//authority][path][?query][#fragment]

//[scheme:]scheme-specific-part[#fragment]

//https://docs.oracle.com/javase/6/docs/api/java/net/URI.html

function TURI.toString():RawByteString; inline;
begin
 Result:=FURI;
end;

function TURI.getProtocol():RawByteString;
Var
 R:TURIPart;
begin
 R:=FProtocol;

 While (R.L<>0) and (FURI[R.P+R.L]<=' ') do
 begin
  Dec(R.L);
 end;

 while (R.L<>0) and (FURI[R.P]<=' ')  do
 begin
  Dec(R.L);
  Inc(R.P);
 end;

 Result:=Copy(FURI,R.P,R.L);
end;

function TURI.getScheme():RawByteString; inline;
begin
 Result:=getProtocol();
end;

function TURI.getSchemeSpecificPart(Raw:Boolean=false):RawByteString;
var
 P,L:SizeUint;
begin
 P:=FProtocol.P+FProtocol.L;
 if P=0 then P:=2 else P:=P+1;
 if FRef.P=0 then
 begin
  L:=Length(FURI)-P+1;
 end else
 begin
  L:=FRef.P-P-1;
 end;
 Case Raw of
  True :Result:=Copy(FURI,P,L);
  False:Result:=Unescape(@FURI[P],L);
 end;
end;

function TURI.getUserInfo(Raw:Boolean=false):RawByteString;
var
 P,L:SizeUint;
begin
 P:=FUsername.P;
 if P=0 then P:=FPassword.P;
 L:=FPassword.P+FPassword.L;
 if L=0 then L:=FUsername.P+FUsername.L;
 L:=L-P;
 Case Raw of
  True :Result:=Copy(FURI,P,L);
  False:Result:=Unescape_trim(@FURI[P],L);
 end;
end;

function TURI.getUsername(Raw:Boolean=false):RawByteString;
begin
 Case Raw of
  True :Result:=Copy(FURI,FUsername.P,FUsername.L);
  False:Result:=Unescape_trim(@FURI[FUsername.P],FUsername.L);
 end;
end;

function TURI.getPassword(Raw:Boolean=false):RawByteString;
begin
 Case Raw of
  True :Result:=Copy(FURI,FPassword.P,FPassword.L);
  False:Result:=Unescape_trim(@FURI[FPassword.P],FPassword.L);
 end;
end;

function TURI.getAuthority(Raw:Boolean=false):RawByteString;
var
 P,L:SizeUint;
begin
 P:=FUsername.P;
 if P=0 then P:=FHost.P;
 if P=0 then P:=FPort.P;
 L:=FPort.P+FPort.L;
 if L=0 then L:=FHost.P+FHost.L;
 if L=0 then L:=FPassword.P+FPassword.L;
 if L=0 then L:=FUsername.P+FUsername.L;
 L:=L-P;
 Case Raw of
  True :Result:=Copy(FURI,P,L);
  False:Result:=Unescape_trim(@FURI[P],L);
 end;
end;

function TURI.getHost():RawByteString;
Var
 R:TURIPart;
begin
 R:=FHost;
 if (R.L<>0) and (FURI[R.P+R.L]='.') then
 begin
  Dec(R.L);
 end;
 Result:=Copy(FURI,R.P,R.L);
end;

function TURI.getPort():Word; inline;
begin
 Result:=0;
 if FPort.P<>0 then
 TryPcharToWord(@FURI[FPort.P],FPort.L,Result);
end;

function TURI.getPath(Raw:Boolean=false):RawByteString; inline;
begin
 Case Raw of
  True :Result:=Copy(FURI,FPath.P,FPath.L);
  False:Result:=Unescape_trim(@FURI[FPath.P],FPath.L);
 end;
end;

function TURI.getQuery(Raw:Boolean=false):RawByteString;
begin
 Case Raw of
  True :Result:=Copy(FURI,FQuery.P,FQuery.L);
  False:Result:=UnescapeQuery(@FURI[FQuery.P],FQuery.L);
 end;
end;

function TURI.getRef(Raw:Boolean=false):RawByteString;
begin
 Case Raw of
  True :Result:=Copy(FURI,FRef.P,FRef.L);
  False:Result:=Unescape_trim(@FURI[FRef.P],FRef.L);
 end;
end;

function TURI.getFragment(Raw:Boolean=false):RawByteString; inline;
begin
 Result:=getRef(Raw)
end;

function TURI._get(i:Byte):RawByteString;
var
 R:TURIPart;
begin
 R:=Default(TURIPart);
 case i of
  0:R:=FProtocol;
  1:R:=FUsername;
  2:R:=FPassword;
  3:R:=FHost;
  4:R:=FPort;
  5:R:=FPath;
  6:R:=FQuery;
  7:R:=FRef;
 end;
 Result:=Copy(FURI,R.P,R.L);
end;

{
procedure test_uri;
var
 URI:TURI;
 i:Byte;
begin
 //URI:=parse_uri('wss://user:password@host:80/path/document?arg1=val1&arg2=val2#part',false);
 For i:=0 to 7 do Write(URI._get(i),'*');
 Writeln;

 URI:=parse_uri('wss://user:password@host.org .:80/path/document?arg1=val1&arg2=val2#par',false);
 For i:=0 to 7 do Write(URI._get(i),'*');
 writeln;
 Writeln(URI.GetHost());

end;
}

initialization
  //test_uri;

end.

