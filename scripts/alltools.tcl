# All-Tool TCL, includes toolbox.tcl, toolkit.tcl and moretools.tcl
# toolbox is Authored by cmwagner@sodre.net
# toolkit is Authored by (Someone claim this)[unknown]
# moretools is Authored by David Sesno(walker@shell.pcrealm.net)
# modified for 1.3.0 bots by TG

###################

# Descriptions of ALL the avaliable commands:
## (toolkit):
# newflag <flag> - REMOVED numeric flags are no longer supported in this way
#
# putmsg <nick> <text>
#   sends a message to someone on irc
#
# putnotc <nick> <text>
#   sends a notice to someone on irc
#
# putchan <channel> <text>
#   sends a public message to a channel
#
# putact <channel> <text>
#   does a public action to a channel
#
## (toolbox):
# strlwr <string>
#   string tolower
#
# strupr <string>
#   string toupper
#
# strcmp <string1> <string2>
#   string compare
#
# stricmp <string1> <string2>
#   string compare (insensitive to case)
#
# strlen <string>
#   string lenght
#
# stridx <string> <index>
#   string index
#
# iscommand <command>
#   is a certain command a valid tcl command?
#
# timerexists <timer_proc>
#   check to see if a timer for a certain procedure exists.
#
# utimerexists <utimer_proc>
#   check to see if a utimer for a certain procedure exists
#
# inchain <bot>
#   is a bot in the chain?
#
# randstring <length>
#   generate a string with random characters in it.
#
# putdccall <msg>
#   send text to all dcc users
#
# putdccbut <idx> <msg>
#   send text to all dcc users but idx.
#
# [killdccall]
#   kill all dcc users
#
# killdccbut <idx>
#   kill dcc users but idx
#
# valididx <idx>
#   check to see if idx is in dcclist, if it is returns 1
#
## (moretools):
# testip <host/ip>
#   test a host to see if it is an ip, if it is returns 1
#
# number_to_number <digit>
#   converts a digit, 1-15, to an analog Numeral
# 
# [realtime]
#   Returns the "realtime" in standard format, with am/pm, as oppsed to
#   [time] returning the military format.
#
# iso <nick> <#channel>
#   returns 1 if the 'nick'(not hand) has +o access on '#channel' (by dtm)
#
#########################

# So scripts can see if allt is loaded.
set alltools_loaded 1
set allt_version 101

# For backward comptibility.
set toolbox_revision 1005
set toolbox_loaded 1
set toolkit_loaded 1


# Procs.............
proc number_to_number {domaintocount} {
  if {$domaintocount == "0"} {set numeral "Zero"}
  if {$domaintocount == "1"} {set numeral "One"}
  if {$domaintocount == "2"} {set numeral "Two"}
  if {$domaintocount == "3"} {set numeral "Three"}
  if {$domaintocount == "4"} {set numeral "Four"}
  if {$domaintocount == "5"} {set numeral "Five"}
  if {$domaintocount == "6"} {set numeral "Six"}
  if {$domaintocount == "7"} {set numeral "Seven"}
  if {$domaintocount == "8"} {set numeral "Eight"}
  if {$domaintocount == "9"} {set numeral "Nine"}
  if {$domaintocount == "10"} {set numeral "Ten"}
  if {$domaintocount == "11"} {set numeral "Eleven"}
  if {$domaintocount == "12"} {set numeral "Twelve"}
  if {$domaintocount == "13"} {set numeral "Thirteen"}
  if {$domaintocount == "14"} {set numeral "Fourteen"}
  if {$domaintocount == "15"} {set numeral "Fifteen"}
  if {$numeral == ""} {set $numeral $domaintocount}
  return $numeral
}

proc testip {address} {
 set testhost [split $address "."]
 if {[llength $testhost]==4} {
  if {[string length [lindex $testhost 0]]<4 &&
   [string length [lindex $testhost 1]]<4 &&
   [string length [lindex $testhost 2]]<4 &&
   [string length [lindex $testhost 4]]<4} {
    if {[lindex $testhost 0] < 256 &&
     [lindex $testhost 1] < 256 &&
     [lindex $testhost 2] < 256 &&
     [lindex $testhost 3] < 256} {
      return 1
    }
  }
 } {
  return 0
 }
}

proc realtime {} {
  set time1 [lindex [split [time] :] 0]
  set timestat "am"
  set time2 "$time1"
  if {($time1>12) || ($time1 == "00")} {
    set timestat "pm"
    if {$time1 == "13"} {set time2 "1"}
    if {$time1 == "14"} {set time2 "2"}
    if {$time1 == "15"} {set time2 "3"}
    if {$time1 == "16"} {set time2 "4"}
    if {$time1 == "17"} {set time2 "5"}
    if {$time1 == "18"} {set time2 "6"}
    if {$time1 == "19"} {set time2 "7"}
    if {$time1 == "20"} {set time2 "8"}
    if {$time1 == "21"} {set time2 "9"}
    if {$time1 == "22"} {set time2 "10"}
    if {$time1 == "23"} {set time2 "11"}
    if {$time1 == "00"} {set time2 "12"}
    if {$time1 == "24"} {set time2 "12"}
    # Someone told me to add the above line. Does [time] return 24? (=
  }
  set time3 [lindex [split [time] :] 1]
  set realtime "[string trimleft $time2 0]:${time3}"
  return "${realtime}${timestat}"
}

proc iso {nick chan1} {
 return [matchattr [nick2hand $nick $chan1] o|o $chan1]
}

proc putmsg {nick text} {
  putserv "PRIVMSG $nick :$text"
}

proc putnotc {nick text} {
  putserv "NOTICE $nick :$text"
}

proc putchan {chan text} {
  putserv "PRIVMSG $chan :$text"
}

proc putact {chan text} {
  putserv "PRIVMSG $chan :\001ACTION $text\001"
}

proc strlwr {string} {
   return [string tolower $string]
}

proc strupr {string} {
   return [string toupper $string]
}

proc strcmp {string1 string2} {
   return [string compare $string1 $string2]
}

proc stricmp {string1 string2} {
   return [string compare [strlwr $string1] [strlwr $string2]]
}

proc strlen {string} {
   return [string length $string]
}

proc stridx {string index} {
   return [string index $string $index]
}

proc iscommand {command} {
   if {[lsearch -exact [strlwr [info commands]] [strlwr $command]] != -1} {
      return 1
   }

   return 0
}

proc timerexists {timer_proc} {
   foreach j [timers] {
      if {[string compare [lindex $j 1] $timer_proc] == 0} {
         return [lindex $j 2]
      }
   }
}

if {[iscommand utimers]} {
   proc utimerexists {timer_proc} {
      foreach j [utimers] {
         if {[string compare [lindex $j 1] $timer_proc] == 0} {
            return [lindex $j 2]
         }
      }
   }
}

proc inchain {bot} {
   if {[lsearch -exact [strlwr [bots]] [strlwr $bot]] != -1} {
      return 1
   }

   return 0
}

proc randstring {count} {
  set rs ""
  for {set j 0} {$j < $count} {incr j} {
     set x [rand 62]
     append rs [string range "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" $x $x]
  }

  unset x
  unset j
  return $rs
}

proc putdccall {msg} {
   foreach j [dcclist] {
      putdcc [lindex $j 0] $msg
   }
}

proc putdccbut {idx msg} {
   foreach j [dcclist] {
      if {[lindex $j 0] != $idx} {
         putdcc [lindex $j 0] $msg
      }
   }
}

proc killdccall {} {
   foreach j [dcclist] {
      killdcc [lindex $j 0]
   }
}

proc killdccbut {idx} {
   foreach j [dcclist] {
      if {[lindex $j 0] != $idx} {
         killdcc [lindex $j 0]
      }
   }
}

proc valididx {idx} {
   set r 0
   foreach j [dcclist] {
      if {[lindex $j 0] == $idx} {
          set r 1
          break
      }
   }

   return $r
}
