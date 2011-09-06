# eggcompat.tcl: Eggdrop commands implementation via FoxEye commands.
#
# assuming tcl gets everything as eggdrop does, i.e. one-network target
#
# Copyright (C) 2010-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>

# that's too rough, don't use $botnick but [botnick] instead
#global irc_default_nick botnick
#set botnick $irc_default_nick

#
# a minimal multinetwork support
#
global tcl_last_network
set tcl_last_network $tcl_default_network

#
# some mostly standard functions
#
proc rand {max} {
  return [expr {int(rand()*$max) + 1}]
}

# base procedure nick@net => nick, channel@net => channel
proc client2name {client} {
  global tcl_last_network
  set atdog [string last @ [string range $client 1 end]]
  if {$atdog < 0} {
    return $client
  }
  # set it here assuming it is first conversion in the proc
  set tcl_last_network [string range $client [expr $atdog + 2] end]
  return [string range $client 0 $atdog]
}

# base procedure nick => nick@net, channel => channel@net
proc name2client {name} {
  global tcl_last_network
  return "[client2name $name]@$tcl_last_network"
}

#
# derivatives from: send_request to type mode text
#

# putserv <text> [options]
proc putserv {text {opt ""}} {
  global tcl_last_network
  if {$opt == "-next"} {
    send_request $tcl_last_network - 0 "$text"
  } {
    send_request $tcl_last_network n 0 "$text"
  }
}
# puthelp <text> [options]
proc puthelp {text {opt ""}} {
  putserv "$text" $opt
}
# putquick <text> [options]
proc putquick {text {opt ""}} {
  putserv "$text" $opt
}
# putkick <channel> <nick,nick,...> [reason]
proc putkick {channel nicklist reason} {
  putserv "KICK $channel $nicklist :$reason"
}
# putlog <text>
proc putlog {text} {
  send_request * l o "$text"
}
# putcmdlog <text>
proc putcmdlog {text} {
  send_request * l c "$text"
}
# putxferlog <text>
# putloglev <level(s)> <channel> <text>
proc putloglev {levels channel text} {
  send_request [name2client $channel] l "$levels" "$text"
}
# pushmode <channel> <mode> [arg]
proc pushmode {channel mode {args ""}} {
  putserv "MODE [client2name $channel] $mode $args"
}
# putmsg <nick> <text>
proc putmsg {nick text} {
  send_request [name2client $nick] c 0 "$text"
}
# putnotc <nick> <text>
proc putnotc {nick text} {
  send_request [name2client $nick] c 1 "$text"
}
# putctcp <nick> <text>
proc putctcp {nick text} {
  send_request [name2client $nick] c 2 "$text"
}
# putchan <channel> <text>
proc putchan {channel text} {
  send_request [name2client $channel] c 0 "$text"
}
# putact <channel> <text>
proc putact {channel text} {
  send_request [name2client $channel] c 4 "$text"
}
# putdcc <idx> <text>
proc putdcc {idx text} {
  send_request ":$idx:*" d 0 "$text"
}

#
# derivatives from: ison service [lname]
#

# handonchan <handle> <channel>
proc handonchan {lname channel} {
  if {[ison [name2client $channel] $lname] == ""} {
    return 1
  } {
    return 0
  }
}
# hand2nick <handle> [channel]
proc hand2nick {lname {channel ""}} {
  global tcl_last_network
  if {"$channel" == ""} {
    return [ison $tcl_last_network $lname]
  } {
    return [ison [name2client $channel] $lname]
  }
}
# botnick - use [botnick] instead of $botnick
proc botnick {} {
  global tcl_last_network
  return [ison $tcl_last_network]
}
# isbotnick <nick>
proc isbotnick {nick} {
  global tcl_last_network
  if {$nick == [botnick]} {
    return 1
  } {
    return 0
  }
}

#
# derivatives from: check_flags lname flags [service]
#

# matchattr <handle> <flags> [channel]
proc matchattr {lname attr {channel ""}} {
  if {"$channel" == ""} {
    return [check_flags $lname $attr]
  } {
    return [check_flags $lname $attr [name2client $channel]]
  }
}

#
# derivatives from: utimer <time> <cmd>
#

# timer <time> <cmd>
proc timer {val cmd} {
  return [utimer [expr $val * 60] "$cmd"]
}

#
# derivatives from: killutimer <timerID>
#

# killtimer <timerID>
proc killtimer {timerid} {
  killutimer $timerid
}
