#
# Regular cron jobs for the rtpinsertsound package
#
0 4	* * *	root	[ -x /usr/bin/rtpinsertsound_maintenance ] && /usr/bin/rtpinsertsound_maintenance
