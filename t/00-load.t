#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'KSM::Daemon' ) || print "Bail out!
";
}

diag( "Testing KSM::Daemon $KSM::Daemon::VERSION, Perl $], $^X" );
