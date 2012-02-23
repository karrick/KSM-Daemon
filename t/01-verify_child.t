#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use Test::More;
use Test::Class;
use base qw(Test::Class);
END { Test::Class->runtests }

########################################

use KSM::Daemon qw(:all);

########################################
# verify_child

sub test_verify_child_croaks_when_child_bad : Tests {
    eval {KSM::Daemon::verify_child()};
    like($@, qr/\bchild should be reference to a hash\b/);

    eval {KSM::Daemon::verify_child([])};
    like($@, qr/\bchild should be reference to a hash\b/);
}

####################
# name

sub test_verify_child_checks_name : Tests {
    eval {KSM::Daemon::verify_child({})};
    like($@, qr/\bchild name should be string\b/);

    eval {KSM::Daemon::verify_child({name => {}})};
    like($@, qr/\bchild name should be string\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}}));
}

####################
# function

sub test_verify_child_checks_function : Tests {
    eval {KSM::Daemon::verify_child({name => 'test'})};
    like($@, qr/\bchild function should be a function\b/);

    eval {KSM::Daemon::verify_child({name => 'test', function => 'foo'})};
    like($@, qr/\bchild function should be a function\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}}));
}

####################
# signals

sub test_verify_child_checks_signals : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => '1'})};
    like($@, qr/\bchild signals should be reference to array\b/);

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => ['HUP','ALRM']})->{signals},
	      ['TERM','INT','HUP','ALRM'], "should add TERM and INT when neither found");

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => ['HUP','ALRM','TERM']})->{signals},
	      ['INT','HUP','ALRM','TERM'], "should add INT when not found");

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, signals => ['HUP','INT','ALRM']})->{signals},
	      ['TERM','HUP','INT','ALRM'], "should add TERM when not found");
}

sub test_verify_child_signals_default : Tests {
    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{signals},
	      ['TERM','INT'], "should add TERM and INT when no signals requested");
}

####################
# args

sub test_verify_child_checks_function_checks_args : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, args => '1'})};
    like($@, qr/\bchild args should be reference to array\b/);

    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}, args => ["one",2]})->{args}, 
	      ["one",2]);
}

sub test_verify_child_checks_function_args_default : Tests {
    is_deeply(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{args}, []);
}

####################
# restart, error

sub test_verify_child_checks_function_checks_restart : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, restart => []})};
    like($@, qr/\bchild restart should be a scalar\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}, restart => 1}));;
}

sub test_verify_child_checks_function_checks_error : Tests {
    eval {KSM::Daemon::verify_child({name => 'test', function => sub {1}, error => []})};
    like($@, qr/\bchild error should be a scalar\b/);

    ok(KSM::Daemon::verify_child({name => 'test', function => sub {1}, error => 1}));;
}

sub test_verify_child_checks_function_restart_default : Tests {
    is(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{restart}, 0);
}

sub test_verify_child_checks_function_error_default : Tests {
    is(KSM::Daemon::verify_child({name => 'test', function => sub {1}})->{error}, 0);
}

########################################
# verify_children

sub test_verify_children_checks_children : Tests {
    eval {KSM::Daemon::verify_children()};
    like($@, qr/\bchildren should be reference to array\b/);
    eval {KSM::Daemon::verify_children({})};
    like($@, qr/\bchildren should be reference to array\b/);
    eval {KSM::Daemon::verify_children([])};
    like($@, qr/\bchildren should have at least one child\b/);
}

sub test_verify_children_checks_each_child : Tests {
    # first child
    eval {KSM::Daemon::verify_children([{name => 'foo'},
					{name => 'bar', function => sub {1}},
					{name => 'baz', function => sub {1}}])};
    like($@, qr/\bunable to verify children\b/);
    like($@, qr/\bchild function should be\b/);

    # middle child
    eval {KSM::Daemon::verify_children([{name => 'foo', function => sub {1}},
					{function => sub {1}},
					{name => 'baz', function => sub {1}}])};
    like($@, qr/\bunable to verify children\b/);
    like($@, qr/\bchild name should be\b/);

    # last child
    eval {KSM::Daemon::verify_children([{name => 'foo', function => sub {1}},
					{name => 'bar', function => sub {1}},
					{name => 'baz', function => sub {1}, args => 1}])};
    like($@, qr/\bunable to verify children\b/);
    like($@, qr/\bchild args should be\b/);
}
