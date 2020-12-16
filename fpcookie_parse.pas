{ cookie field parser

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

unit fpcookie_parse;

{$mode objfpc}{$H+}

interface

uses
 SysUtils;

type
 TStrVal=object
  FStr:PChar;
  FLen:SizeUInt;
  function GetStr:RawByteString; inline;
 end;
 TCookieCb=procedure(name,value:TStrVal;data:Pointer);

 PSetCookie=^TSetCookie;
 TSetCookie=record
  name,value,Domain,Path:TStrVal;
  time:Int64;
  Flags:set of (cfInit,cfExpires,cfMaxAge,cfSecure,cfHttpOnly,cfStrict,cfLax,cfNone);
 end;

Procedure parse_cookie(P:PChar;len:SizeUint;cb:TCookieCb;data:Pointer);
function  parse_set_cookie(P:PChar;len:SizeUint):TSetCookie;
function  TryExpiresToUnixTime(P:PAnsiChar;Len:SizeUInt;Out time:Int64):boolean;

implementation

function TStrVal.GetStr:RawByteString; inline;
begin
 SetString(Result,FStr,FLen);
end;

Procedure _Trim(var V:TStrVal); inline;
Var
 i:SizeUInt;
begin
 if (V.FStr=nil) or (V.FLen=0) then Exit;
 while (V.FLen<>0) and (V.FStr^<=' ') do
 begin
  Dec(V.FLen);
  Inc(V.FStr);
 end;
 While (V.FLen<>0) do
 begin
  i:=V.FLen-1;
  if (V.FStr[i]>' ') then Exit;
  V.FLen:=i;
 end;
end;

Procedure parse_cookie(P:PChar;len:SizeUint;cb:TCookieCb;data:Pointer);
Var
 i:SizeInt;

 procedure _on_field(P:PChar;len:SizeUint);
 Var
  i:SizeInt;
  name,value:TStrVal;
 begin
  if (len<>0) then
  begin
   i:=System.IndexByte(P^,len,Byte('='));

   if (i=-1) then
   begin
    name.FStr:=P;
    name.FLen:=len;
    value.FStr:=nil;
    value.FLen:=0;
   end else
   begin
    name.FStr:=P;
    name.FLen:=i;
    value.FStr:=@P[i+1];
    value.FLen:=Len-i-1;
   end;

   _Trim(name);
   _Trim(value);

   if (name.FLen<>0) then
   begin
    cb(name,value,data);
   end;

  end;
 end;

begin
 if (P=nil) or (len=0) or (cb=nil) then Exit;

 repeat
  i:=System.IndexByte(P^,len,Byte(';'));

  if (i=-1) then
  begin
   _on_field(P,len);
   Exit;
  end;

  _on_field(P,i);
  P:=@P[i+1];
  Len:=Len-i-1;

 until false;
end;


function _on_set_cookie_name(data:Pointer;len:SizeUInt):SizeInt; inline;
begin
 Result:=-1;
 if (data=nil) or (len=0) then Exit;
 Case len of
  4:Case PDWord(Data)^ or $20202020 of
     $68746170:Result:=3; //path
    end;
  6:Case PDWord(Data)^ or $20202020 of
     $616D6F64: //doma
               Case PWord(Data)[2] or $2020 of
                $6E69:Result:=2; //in
               end;
     $75636573: //secu
               Case PWord(Data)[2] or $2020 of
                $6572:Result:=4; //re
               end;
    end;
  7:Case (PQWord(Data)^ and $FFFFFFFFFFFFFF) or $20202000202020  of
     $73657249707865,           //expIres
     $73657269707865:Result:=0; //expires
     $6567612D78616D:Result:=1; //max-age
    end;
  8:Case PQWord(Data)^ or $2020202020202020 of
     $796C6E6F70747468:Result:=5; //httponly
     $65746973656D6173:Result:=6; //samesite
    end;
 end;
end;

function _on_samesite(data:Pointer;len:SizeUInt):SizeInt; inline;
begin
 Result:=-1;
 if (data=nil) or (len=0) then Exit;
 Case len of
  3:Case (PDWord(Data)^ and $FFFFFF) or $202020 of
     $78616C:Result:=1; //lax
    end;
  4:Case PDWord(Data)^ or $20202020 of
     $656E6F6E:Result:=2; //none
    end;
  6:Case PDWord(Data)^ or $20202020 of
     $69727473: //stri
               Case PWord(Data)[2] or $2020 of
                $7463:Result:=0; //ct
               end;
    end;
 end;
end;

function TryMaxAgeToUnixTime(P:PAnsiChar;Len:SizeUInt;Out time:Int64):boolean;
Var
 R,T:Int64;
 b:Byte;
 min:Boolean;
begin
 Result:=False;
 if (P=nil) or (Len=0) or (Len>20) then Exit;
 R:=0;
 min:=False;
 Case P^ of
  '+':begin
       Inc(P);
       Dec(Len);
      end;
  '-':begin
       Inc(P);
       Dec(Len);
       min:=True;
      end;
 end;
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
 if min then R:=-R;
 time:=R;
 Result:=True;
end;

function TryEncodeUnixTime(Hour,Min,Sec:Word;Out Time:cardinal):boolean; inline;
begin
 Result:=(Hour<24) and (Min<60) and (Sec<60);
 If Result then
 begin
  Time:=cardinal(Hour)*3600+cardinal(Min)*60+cardinal(Sec);
 end;
end;

Function TryEncodeUnixDate(Year,Month,Day:Word;Out Date:cardinal):Boolean; inline;
var
 c,ya:cardinal;
begin
 Result:=(Year>0) and (Year<10000) and
         (Month in [1..12]) and
         (Day>0) and (Day<=MonthDays[IsleapYear(Year),Month]);
 if Result then
 begin
  if month > 2 then
   Dec(Month,3)
  else
  begin
   Inc(Month,9);
   Dec(Year);
  end;
  c:= Year DIV 100;
  ya:= Year - 100*c;
  Date := (146097*c) SHR 2 + (1461*ya) SHR 2 + (153*cardinal(Month)+2) DIV 5 + cardinal(Day);
 end
end;

function _on_month_822(data:Pointer):Word; inline;
begin
 Result:=0;
 Case PDWord(Data)^ of
  $206E614A:Result:=01; //Jan
  $20626546:Result:=02; //Feb
  $2072614D:Result:=03; //Mar
  $20727041:Result:=04; //Apr
  $2079614D:Result:=05; //May
  $206E754A:Result:=06; //Jun
  $206C754A:Result:=07; //Jul
  $20677541:Result:=08; //Aug
  $20706553:Result:=09; //Sep
  $2074634F:Result:=10; //Oct
  $20766F4E:Result:=11; //Nov
  $20636544:Result:=12; //Dec
 end;
end;

function _on_month_850(data:Pointer):Word; inline;
begin
 Result:=0;
 Case PDWord(Data)^ of
  $2D6E614A:Result:=01; //Jan-
  $2D626546:Result:=02; //Feb-
  $2D72614D:Result:=03; //Mar-
  $2D727041:Result:=04; //Apr-
  $2D79614D:Result:=05; //May-
  $2D6E754A:Result:=06; //Jun-
  $2D6C754A:Result:=07; //Jul-
  $2D677541:Result:=08; //Aug-
  $2D706553:Result:=09; //Sep-
  $2D74634F:Result:=10; //Oct-
  $2D766F4E:Result:=11; //Nov-
  $2D636544:Result:=12; //Dec-
 end;
end;

function _on_wkday_822(data:Pointer):Boolean; inline;
begin
 Result:=false;
 Case PDWord(Data)^ of
  $2C697246,              //Fri,
  $2C6E6F4D,              //Mon,
  $2C746153,              //Sat,
  $2C6E7553,              //Sun,
  $2C756854,              //Thu,
  $2C657554,              //Tue,
  $2C646557:Result:=true; //Wed,
 end;
end;

function _on_wkday_asc(data:Pointer):Boolean; inline;
begin
 Result:=false;
 Case PDWord(Data)^ of
  $20697246,              //Fri
  $206E6F4D,              //Mon
  $20746153,              //Sat
  $206E7553,              //Sun
  $20756854,              //Thu
  $20657554,              //Tue
  $20646557:Result:=true; //Wed
 end;
end;

function _on_weekday(data:Pointer):cardinal; inline;
begin
 Result:=0;
 Case PQWord(Data)^ of
  $202C796164697246,           //Friday,
  $202C7961646E6F4D,           //Monday,
  $202C7961646E7553:Result:=6; //Sunday,
  $2C79616473657554:Result:=7; //Tuesday,
  $7961647275746153,           //Saturday
  $7961647372756854:Result:=8; //Thursday
  $616473656E646557: //Wednesda
                    Case PByte(Data)[8] of
                     $79:Result:=9; //y
                    end;
 end;
end;

function _on_get2num(data:PAnsiChar;Var R:Word):Boolean; inline;
begin
 Result:=False;
 Case data[0] of
  '0'..'9':R:=(Byte(data[0])-Byte('0'))*10;
  else Exit;
 end;
 Case data[1] of
  '0'..'9':R:=R+(Byte(data[1])-Byte('0'));
  else Exit;
 end;
 Result:=True;
end;

function _on_get2num_asc(data:PAnsiChar;Var R:Word):Boolean; inline;
begin
 Result:=False;
 Case data[0] of
       ' ':R:=0;
  '0'..'9':R:=(Byte(data[0])-Byte('0'))*10;
  else Exit;
 end;
 Case data[1] of
  '0'..'9':R:=R+(Byte(data[1])-Byte('0'));
  else Exit;
 end;
 Result:=True;
end;

function _on_get4num(data:PAnsiChar;Var R:Word):Boolean; inline;
begin
 Result:=False;
 Case data[0] of
  '0'..'9':R:=(Byte(data[0])-Byte('0'))*1000;
  else Exit;
 end;
 Case data[1] of
  '0'..'9':R:=R+(Byte(data[1])-Byte('0'))*100;
  else Exit;
 end;
 Case data[2] of
  '0'..'9':R:=R+(Byte(data[2])-Byte('0'))*10;
  else Exit;
 end;
 Case data[3] of
  '0'..'9':R:=R+(Byte(data[3])-Byte('0'));
  else Exit;
 end;
 Result:=True;
end;

function TryExpiresToUnixTime(P:PAnsiChar;Len:SizeUInt;Out time:Int64):boolean;
const
 SecsPerDay=86400;
 delta_time=62162121600;
 GMT=$544D4720;
 W8=$202C;
type
 TRfcDateTime=packed record
  Yer,Mon,Day,
  Hor,Min,Sec:Word;
 end;
Var
 R:TRfcDateTime;
 _Date,_Time:cardinal;
begin
 Result:=False;
 if (P=nil) or (len=0) then Exit;
 R:=Default(TRfcDateTime);
 Case len of
  29:begin //RFC 822
      if not _on_wkday_822(P) then Exit;
      P:=@P[4];
      if (P^<>' ') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Day) then Exit;
      P:=@P[2];
      if (P^<>' ') then Exit;
      P:=@P[1];
      R.Mon:=_on_month_822(P);
      if (R.Mon=0) then Exit;
      P:=@P[4];
      if not _on_get4num(P,R.Yer) then Exit;
      P:=@P[4];
      if (P^<>' ') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Hor) then Exit;
      P:=@P[2];
      if (P^<>':') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Min) then Exit;
      P:=@P[2];
      if (P^<>':') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Sec) then Exit;
      P:=@P[2];
      if PDWord(P)^<>GMT then Exit;
     end;
  30..33: //RFC 850
     begin
      _Time:=_on_weekday(P);
      Case _Time of
       6:begin
          if (Len<>30) then Exit;
          P:=@P[8];
         end;
       7:begin
          if (Len<>31) then Exit;
          P:=@P[8];
          if (P^<>' ') then Exit;
          P:=@P[1];
         end;
       8:begin
          if (Len<>32) then Exit;
          P:=@P[8];
          if PWord(P)^<>W8 then Exit;
          P:=@P[2];
         end;
       9:begin
          if (Len<>33) then Exit;
          P:=@P[9];
          if PWord(P)^<>W8 then Exit;
          P:=@P[2];
         end;
       else Exit;
      end;
      if not _on_get2num(P,R.Day) then Exit;
      P:=@P[2];
      if (P^<>'-') then Exit;
      P:=@P[1];
      R.Mon:=_on_month_850(P);
      if (R.Mon=0) then Exit;
      P:=@P[4];
      if not _on_get2num(P,R.Yer) then Exit;
      R.Yer:=R.Yer+1900;
      P:=@P[2];
      if (P^<>' ') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Hor) then Exit;
      P:=@P[2];
      if (P^<>':') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Min) then Exit;
      P:=@P[2];
      if (P^<>':') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Sec) then Exit;
      P:=@P[2];
      if PDWord(P)^<>GMT then Exit;
     end;
  24:begin //asctime
      if not _on_wkday_asc(P) then Exit;
      P:=@P[4];
      R.Mon:=_on_month_822(P);
      if (R.Mon=0) then Exit;
      P:=@P[4];
      if not _on_get2num_asc(P,R.Day) then Exit;
      P:=@P[2];
      if (P^<>' ') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Hor) then Exit;
      P:=@P[2];
      if (P^<>':') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Min) then Exit;
      P:=@P[2];
      if (P^<>':') then Exit;
      P:=@P[1];
      if not _on_get2num(P,R.Sec) then Exit;
      P:=@P[2];
      if (P^<>' ') then Exit;
      P:=@P[1];
      if not _on_get4num(P,R.Yer) then Exit;
     end;
 end;
 Result:=TryEncodeUnixTime(R.Hor,R.Min,R.Sec,_Time) and
         TryEncodeUnixDate(R.Yer,R.Mon,R.Day,_Date);
 if Result then
 begin
  time:=_Time+Int64(_Date)*SecsPerDay-delta_time;
 end;
end;

//[Sun,][ ][06][ ][Nov ][1994][ ]08:49:37 GMT
//[Sunday, ]06-Nov-94 08:49:37 GMT
//[Sun ][Nov ][ 6] 08:49:37 1994

procedure _on_set_cookie(cname,cvalue:TStrVal;data:Pointer);
begin
 with PSetCookie(data)^ do
 begin
  if (cfInit in Flags) then
  begin
   case _on_set_cookie_name(cname.FStr,cname.FLen) of
    0:if not (cfMaxAge in Flags) then //Expires
       if TryExpiresToUnixTime(cvalue.FStr,cvalue.FLen,time) then
       begin
        Flags:=Flags+[cfExpires];
       end;
    1:if TryMaxAgeToUnixTime(cvalue.FStr,cvalue.FLen,time) then //Max-Age
      begin
       Flags:=Flags+[cfMaxAge]-[cfExpires];
      end;
    2:Domain:=cvalue;//Domain
    3:Path  :=cvalue;//Path
    4:Flags:=Flags+[cfSecure];  //Secure
    5:Flags:=Flags+[cfHttpOnly];//HttpOnly
    6:case _on_samesite(cvalue.FStr,cvalue.FLen) of //SameSite
       0:Flags:=Flags+[cfStrict]-[cfLax,cfNone];    //Strict
       1:Flags:=Flags+[cfLax]   -[cfStrict,cfNone]; //Lax
       2:Flags:=Flags+[cfNone]  -[cfStrict,cfLax];  //None
      end;
   end;
  end else
  begin
   Flags:=Flags+[cfInit];
   name :=cname;
   value:=cvalue;
  end;
 end;
end;

function parse_set_cookie(P:PChar;len:SizeUint):TSetCookie;
begin
 Result:=Default(TSetCookie);
 Result.Flags:=[cfLax];
 parse_cookie(P,len,@_on_set_cookie,@Result);
end;

end.

