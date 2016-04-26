dnl We have to include -lnsl on Solaris, use results from main tests
if test "$ac_cv_search_inet_ntop" != no; then :
  if test "$ac_cv_search_inet_ntop" != "none required"; then
    MODLIBS="MODLIBS_irc_ctcp=\"$ac_cv_search_inet_ntop\" ${MODLIBS}"
  fi
fi

