package KSM::Daemon;

use utf8;
use strict;
use warnings;

use Carp;
use Cwd;
use File::Basename ();
use POSIX ":sys_wait_h";
use JSON::XS;

use KSM::Helper qw(:all);
use KSM::Logger qw(:all);

=head1 NAME

KSM::Daemon - The great new KSM::Daemon!

=head1 VERSION

Version 1.1.5

=cut

our $VERSION = '1.1.5';

=head1 SYNOPSIS

The KSM::Daemon module performs daemon management and assists with
logging for your perl programs.  It works in conjunction with
KSM::Logger.

Perhaps a little code snippet.

    use KSM::Logger;
    use KSM::Daemon;

    sub greeting {
	foreach (@_) {
	    print sprintf("Hello, %s!\n", $_);
	}
    }

    sub bar {
	print STDERR "bar\n";
    }

    KSM::Logger::initialize({filename_template => sprintf("%s/log/%s.%%F.%%s.log",
							  POSIX::getcwd,
							  File::Basename::basename($0)),
			     level => KSM::Logger::DEBUG});

    KSM::Daemon::daemonize(
      [{name => "greeter",
	function => \&greeting,
	args => ["Abe", "Barry", "Charlie"],
	restart => 30,
	error => 60,
       },
       {name => "bar writer",
	function => \&bar,
	restart => 30,
	error => 60,
	signals => ['HUP','USR1'],
       }]);
    # NOTE: daemonize will not return unless invocation error
    exit(1);
    ...

=head1 EXPORT

Although nothing is exported by default, the most common functions may
be included by importing the :all tag.  For example:

    use KSM::Daemon qw(:all);

=cut

use Exporter qw(import);
our %EXPORT_TAGS = (
    'proc' => [qw(
	bootstrap
	daemonize
)],
    'all' => [qw(
	alive_p
	bootstrap
	create_pipes
	daemonize
	daemonize_process
	find_child_by_name
	maybe_relay_signal_to_child
	monitor_output
	REAPER
	reconfigure
	send_signal_to_children
	set_process_defaults
	setup_signal_handlers
	spawn_child
	terminate_program
	validate_process
	validate_processes
	verify_child
	verify_children
)],
    );
our @EXPORT_OK = (@{$EXPORT_TAGS{'all'}});

=head1 GLOBALS

There are a few module level variables to maintain state of
KSM::Daemon.

=cut

use constant QUICK_RESPAWN_DELAY => 1;
use constant MONITOR_SELECT_TIMEOUT => 5;

our $respawn = 1;

our $retired = {};		# names of processes to retire
our $children = {};
our $pipes = {};

=head1 SUBROUTINES/METHODS

=head2 bootstrap

This function daemonizes your program according to Perl best practices
in 'man perlipc', and spawns and monitors all the specified processes
in the configuration file.

It will respawn a child process that has terminated. If the child
terminates with a status code of zero, the child will be respawned
after its restart delay. If the child terminates with a non-zero
status code, it will respawn the child after the error delay.

=cut

sub bootstrap {
    my ($config) = @_;

    eval {
	# validate prior to daemonization
	my $children = validate_processes(
	    set_process_defaults(
		decode_json(file_read($config))));
	foreach my $name (keys %$children) {
	    debug("child: [%s]", encode_json($children->{$name}));
	}
    };
    if(my $status = $@) {
	chomp($status);
	croak sprintf("cannot daemonize: [%s]", $status);
    }

    # convert to full path before daemonize
    $config = Cwd::abs_path($config);

    # daemonize_process();
    setup_signal_handlers();
    $SIG{HUP} = sub { info("SIGHUP"); reconfigure($config); };

    reconfigure($config);
    monitor_output($pipes->{log}->{stdin}->{read});
}

=head2 daemonize

This function daemonizes your program according to Perl best practices
in 'man perlipc', and spawns and monitors all the specified functions
in the argument list as a separate process.

It will respawn a child process that has terminated.  If the child
terminates without error, the child will be respawned after its
restart delay.  If the child terminates by error or otherwise, it will
respawn the child after the error delay.

=cut

sub daemonize {
    my ($requested_children) = @_;

    eval { verify_children($requested_children) };
    if(my $status = $@) {
	chomp($status);
	croak sprintf("cannot daemonize: [%s]", $status);
    }

    daemonize_process();
    setup_signal_handlers();
    $SIG{HUP} = sub { send_signal_to_children('HUP') };

    my $procs = {};
    foreach my $child (@$requested_children) {
	my $name = $child->{name};
	$procs->{$name} = $child;
    }

    create_pipes($procs);
    info("SPAWNING CHILDREN");
    foreach (@$requested_children) {
    	spawn_child($_);
    }
    monitor_output($pipes->{log}->{stdin}->{read});
}

=head2 set_process_defaults

Iterate through keys of B<procs> hash, setting the name property of
each hash value to the key, and sets stdout and stderr to log if not
set.

{
    "foo" => { "exec" => ["true"] },
    "bar" => { "exec" => ["false"] },
}

Returns:

{
    "foo" => { "name" => "foo", "exec" => ["true"], stdout => "log", stderr => "log" },
    "bar" => { "name" => "bar", "exec" => ["false"], stdout => "log", stderr => "log" },
}

=cut

sub set_process_defaults {
    my ($procs) = @_;
    foreach my $name (sort keys %$procs) {
	$procs->{$name}->{name} = $name;
	$procs->{$name}->{stdout} ||= 'log';
	$procs->{$name}->{stderr} ||= 'log';

	$procs->{$name}->{error} ||= 0;
	$procs->{$name}->{restart} ||= 0;

	# signal
	$procs->{$name}->{signals} ||= [];
	foreach my $sig (qw(INT TERM)) {
	    if(!any($procs->{$name}->{signals}, sub { shift eq $sig })) {
		unshift(@{$procs->{$name}->{signals}}, $sig);
	    }
	}
    }
    $procs;
}

=head2 verify_children

Verify list of children process hashes is valid.

Dies if error during validation of children hashes.

=cut

sub verify_children {
    my ($children) = @_;

    if(ref($children) ne 'ARRAY') {
	die("children ought be array reference\n");
    } elsif(scalar(@$children) == 0) {
	die("children ought have at least one child\n");
    } else {
	verbose("VERIFYING CHILDREN");
	map {
	    eval { verify_child($_) };
	    if(my $status = $@) {
		chomp($status);
		die sprintf("cannot verify children: %s\n", $status);
	    }
	} @$children;
    }
}

=head2 verify_child

Verify arguments valid and normalize arguments for a given child hash.

Returns child hash if valid, and dies if invalid parameters.

=cut

sub verify_child {
    my ($child) = @_;

    if(ref($child) ne 'HASH') {
	die("child should be reference to a hash\n");
    } elsif(!defined($child->{name}) || ref($child->{name}) ne '') {
	die("child name should be string\n");
    } elsif(defined($child->{user}) && ref($child->{user}) ne '') {
	die("child user should be string\n");
    } elsif(ref($child->{function}) ne 'CODE') {
	die("child function should be a function\n");
    } elsif(defined($child->{signals}) && ref($child->{signals}) ne 'ARRAY') {
	die sprintf("child signals should be reference to array: [%s]\n",
		    ref($child->{signals}));
    } elsif(defined($child->{args}) && ref($child->{args}) ne 'ARRAY') {
	die("child args should be reference to array\n");
    } elsif(defined($child->{restart}) && ref($child->{restart}) ne '') {
	die sprintf("child restart should be a scalar: [%s]\n",
		    ref($child->{restart}));
    } elsif(defined($child->{error}) && ref($child->{error}) ne '') {
	die sprintf("child error should be a scalar: %s\n",
		    ref($child->{error}));
    }

    # set defaults for optional arguments
    $child->{signals} = [] if(!defined($child->{signals}));
    foreach my $sig (qw(INT TERM)) {
	if(!any($child->{signals}, sub { shift eq $sig })) {
	    unshift(@{$child->{signals}}, $sig);
	}
    }
    $child->{args} ||= [];
    $child->{error} ||= 0;
    $child->{restart} ||= 0;
    $child->{stderr} ||= 'log';
    $child->{stdout} ||= 'log';
    $child;
}

=head2 validate_processes

Iterate through keys of B<procs> hash, validating the hash parameters
of each process.

=cut

sub validate_processes {
    my ($procs) = @_;
    my $names = [sort keys %$procs];
    foreach my $name (@$names) {
	validate_process($procs->{$name}, $names);
    }
    $procs;
}

=head2 validate_processes

Verify arguments valid for a given process hash.

Returns child hash if valid, and dies if invalid parameters.

=cut

sub validate_process {
    my ($child,$names) = @_;

    if(ref($child) ne 'HASH') {
	my $ref = ref($child) || (defined($child) ? sprintf("SCALAR: %s", $child) : "undef");
	die sprintf("invalid process specification: ought to be hash: %s\n", $ref);
    } elsif(!exists($child->{name})) {
	die sprintf("invalid process specification: ought to have name: %s\n", encode_json($child));
    } elsif(ref($child->{name}) ne '') {
	die sprintf("invalid process specification: name ought to be scalar: %s\n", encode_json($child));
    } elsif($child->{name} eq 'log') {
	die sprintf("invalid process specification: name ought not be log: %s\n", encode_json($child));
    } elsif(!exists($child->{exec})) {
	die sprintf("invalid process specification: ought to have exec: %s\n", encode_json($child));
    } elsif((ref($child->{exec}) ne 'ARRAY') || scalar(@{$child->{exec}}) == 0) {
	die sprintf("invalid process specification: exec ought to be non-empty array: %s\n", encode_json($child));
    }
    foreach my $stream (qw(stdout stderr)) {
	if($child->{$stream} eq $child->{name}) {
	    die sprintf("invalid process specification: %s ought not match own process name: %s\n", $stream, encode_json($child));
	} elsif($child->{$stream} eq 'log') {
	    # 'log' is valid recipient, but not on the list of process names
	} elsif(!any($names, sub { shift eq $child->{$stream} })) {
	    die sprintf("invalid process specification: %s must match a process name: %s\n", $stream, encode_json($child));
	}
    }
    $child;
}

=head2 daemonize_process

Internal function that daemonizes the process, in accordance with
guidance in 'man perlipc'.

=cut

sub daemonize_process {
    info("DAEMONIZING: %s", File::Basename::basename($0));
    chdir('/') or die sprintf("cannot chdir(/): %s\n", $!);

    open(STDIN, '<', '/dev/null') or die sprintf("cannot read from /dev/null: %s\n", $!);
    open(STDOUT, '>', '/dev/null') or die sprintf("cannot write to /dev/null: %s\n", $!);

    defined(my $pid = fork()) or die sprintf("cannot fork: %s\n", $!);
    exit if $pid;		# parent exits
    POSIX::setsid() or die sprintf("cannot start a new session: %s\n", $!);
    open(STDERR, '>&=', 'STDOUT') or die sprintf("cannot dup stdout: %s\n", $!);
}

=head2 setup_signal_handlers

Internal function that prepares signal handlers for UNIX signals.

=cut

sub setup_signal_handlers {
    $SIG{CHLD}	= \&REAPER;

    $SIG{INT}	= \&terminate_program;
    $SIG{TERM}	= \&terminate_program;
    $SIG{QUIT}	= \&terminate_program;

    $SIG{ILL}	= \&terminate_program;
    $SIG{ABRT}	= \&terminate_program;
    $SIG{FPE}	= \&terminate_program;
    $SIG{SEGV}	= \&terminate_program;
    $SIG{PIPE}	= \&terminate_program;

    # NOTE: rather ignore these rather than pass to children

    $SIG{ALRM}	= sub { send_signal_to_children('ALRM') };
    $SIG{USR1}	= sub { send_signal_to_children('USR1') };
    $SIG{USR2}	= sub { send_signal_to_children('USR2') };

    $SIG{CONT}	= sub { send_signal_to_children('CONT') };
    $SIG{STOP}	= sub { send_signal_to_children('STOP') };
    $SIG{TSTP}	= sub { send_signal_to_children('TSTP') };
    $SIG{TTIN}	= sub { send_signal_to_children('TTIN') };
    $SIG{TTOU}	= sub { send_signal_to_children('TTOU') };
}

=head2 terminate_program

Internal function that acts as the default handler for the TERM signal
to allow a program to perform a controlled exit.

When a TERM signal is received by the master process, Monitor will
send all children processes a TERM signal to allow them to exit, then
it will exit itself.  It does not wait for its children to exit.

=cut

sub terminate_program {
    my ($sig) = @_;
    info("received %s signal: preparing to shut down", $sig);
    $respawn = 0;
    send_signal_to_children('TERM');
}

=head2 send_signal_to_children

Internal function used to relay a signal to children processes.

=cut

sub send_signal_to_children {
    my ($sig) = @_;
    foreach my $pid (keys %$children) {
	maybe_relay_signal_to_child($sig, $children->{$pid})
    }
}

=head2 maybe_relay_signal_to_child

Relays a signal to child iff child requested it.

=cut

sub maybe_relay_signal_to_child {
    my ($sig,$child) = @_;
    if(any($child->{signals}, sub { shift eq $sig })) {
	info('relaying %s signal to child %d (%s)', $sig, $child->{pid}, $child->{name});
	kill($sig, $child->{pid});
    } else {
	info('not relaying %s signal to child %d (%s)', $sig, $child->{pid}, $child->{name});
    }
}

=head2 spawn_child

Internal function that spawns a given child process, redirecting its
standard output and standard error to pipes monitored by the
&monitor_output function.

=cut

sub spawn_child {
    my ($child) = @_;

    my $pid;
    my $name = $child->{name};

    if(!defined($name)) {
	die error("child with no name: [%s]", encode_json($child));
    }

    if($pid = fork()) {
	eval {
	    info('spawned child pid %d [%s]', $pid, $name);
	    # don't overwrite autovivified child
	    $child->{pid} = $pid;
	    foreach my $key (keys %$child) {
		$children->{$pid}->{$key} = $child->{$key};
		debug("key [%s] value [%s] for child [%s]", $key, $child->{$key}, $name);
	    }
	    $children->{$pid}->{name} = $name;
	    $children->{$pid}->{started} = time();
	};
	if(my $status = $@) {
	    chomp($status);
	    die sprintf("PARENT FAILURE: %s\n", $status);
	}
    } elsif(defined($pid)) {
	eval {
	    undef $children;
	    reset_signal_handlers();
	    $0 = $name;		# attempt to set name visible by ps(1)

	    if(exists($child->{delay}) && $child->{delay}) {
		verbose('child [%s] snooze %g seconds', $name, $child->{delay});
		sleep($child->{delay});
	    }

	    # I really do not like changing the user in this code
	    if($child->{user}) {
		my ($uid,$gid) = ((getpwnam($child->{user}))[2,3]);
		if(defined($uid) && defined($gid)) {
		    # NOTE: must change gid prior to changing uid
		    if($) != $gid) {
			$) = $gid;
			if($) != $gid) {
			    die sprintf("cannot change gid (%d): [%s]\n", $gid, $!);
			}
			verbose("changed gid (%s)\n", $gid);
		    }
		    if($> != $uid) {
			$> = $uid;
			if($> != $uid) {
			    die sprintf("cannot change uid (%d): [%s]\n", $uid, $!);;
			}
			verbose("changed uid (%s)\n", $uid);
		    }
		} else {
		    die sprintf("unknown user (%s)\n", $child->{user});
		}
	    }

	    verbose("setting up io streams: [%s]", $name);
	    if(defined($pipes->{$name}->{stdin})) {
		debug("redirecting stdin: [%s]", $name);
		open(STDIN, '<', $pipes->{$name}->{stdin}->{read})
		    or die sprintf("cannot redirect STDIN: [%s]\n", $!);
	    }
	    debug("redirecting stdout: [%s]", $name);
	    open(STDOUT, '>&', $pipes->{$name}->{stdout})
		or die sprintf("cannot redirect STDOUT: [%s]\n", $!);
	    debug("redirecting stderr: [%s]", $name);
	    open(STDERR, '>&', $pipes->{$name}->{stderr})
		or die sprintf("cannot redirect STDERR: [%s]\n", $!);

	    if(ref($child->{exec}) eq 'ARRAY') {
		debug("child [%s] exec [%s]", $name, join(" ", @{$child->{exec}}));
		exec {$child->{exec}->[0]} @{$child->{exec}};
		die sprintf("cannot exec: [%s]: %s\n", join(" ", @{$child->{exec}}), $!);
	    } elsif(ref($child->{function}) eq 'CODE') {
		$child->{function}->(@{$child->{args}});
		POSIX::_exit(0);
	    }
	    die "child neither array nor code; not sure why validation failed\n";
	};
	if(my $status = $@) {
	    chomp($status);
	    error("CHILD FAILURE: [%s]\n", $status);
	    POSIX::_exit(1);
	}
	die "NOTREACHED";
    } else {
	die sprintf("cannot fork: [%s]\n", $!);
    }
    $children->{$pid};
}

=head2 monitor_output

Internal function that monitors two pipes, one for standard output and
one for standard input.  Data sent to standard output is redirected to
the log file in the form of an INFO message.  Data sent to standard
error is redirected to the log file in the form of an WARN message.

Because this uses the select(2) OS call to monitor two pipes, it must
use the Perl B<sysread> function to read from the pipe, as one cannot
mix buffered and unbuffered I/O.

=cut

sub monitor_output {
    my ($file_handle) = @_;

    info("MONITORING OUTPUT");

    my ($error_message,$rin,$buffer) = ("","","");
    my $output_handler = sub { my ($line) = @_; chomp($line); info("CHILD: [%s]", $line) };
    my $file_descriptor = fileno($file_handle);
    vec($rin, $file_descriptor, 1) = 1;

    do {
	eval {
	    my $nfound = select(my $rout=$rin, undef, undef, MONITOR_SELECT_TIMEOUT);
            if($nfound == -1) {
                if($!{EINTR} == 0) {
                    # ignore
                } elsif($!{ENOTTY} == 0) {
                    # ignore but log
                    verbose("cannot select (monitored process terminated?): [%s]\n", $!);
                } else {
                    die("cannot select: [%s]\n", $!);
                }
	    } elsif($nfound > 0) {
                if(vec($rout, $file_descriptor, 1) == 1) {
                    $buffer = sysread_spooler($file_handle, $buffer, $output_handler);
                }
	    }
	    handle_expired_children();
	};
	if($@) {
	    chomp($error_message = $@);
	}
    } while(scalar keys %$children);
    if($error_message && $error_message ne 'eof') {
	die sprintf("%s\n", $error_message);
    }

    info("all children terminated; exiting");
    exit;
}

=head2 handle_expired_children

Look for children that have been reaped, log each's termination
information.

If the monitor has not received the signal to quit and the process has
not been placed on the retirement list, then respawn that process.

Otherwise, close file handles and remove process from records.

=cut

sub handle_expired_children {
    debug("handle_expired_children");
    my $time = time();
    foreach my $pid (keys %$children) {
	debug("checking if child terminated: pid %d", $pid);
	if(!alive_p($children->{$pid}->{pid})) {
	    my $child = $children->{$pid};
	    delete $children->{$pid};

	    my $name = $child->{name} || "child-process-that-died-before-parent-setup-complete";
	    verbose("expired child: [%s]", $name);

	    my ($status,$signal);
	    if(defined($child->{status})) {
		$status = $child->{status} >> 8;
		$signal = $child->{status} & 127;

		if($status) {
		    $child->{delay} = $child->{error};
		} else {
		    $child->{delay} = $child->{restart};
		}
	    } else {
		$status = "unknown";
		$child->{delay} = QUICK_RESPAWN_DELAY;
	    }
	    my $received = (defined($signal) ?
			    sprintf(" received signal %d and", $signal) :
			    "");
	    my $duration = (defined($child->{started}) ?
			    $time - $child->{started} :
			    "?");
	    info("child [%s] (pid %d)%s terminated status code %s after %s seconds",
		 $name, $pid, $received, $status, $duration);

	    delete $child->{pid};
	    delete $child->{started};
	    delete $child->{duration};
	    if($respawn) {
		if(defined(my $name = $child->{name})) {
		    if(defined($retired->{$name})) {
			delete $retired->{$name};
			debug("closing retired process stdin file handles: %s", $name);
			if(defined($pipes->{$name}) &&
			   defined($pipes->{$name}->{stdin})) {
			    foreach my $end (qw(read write)) {
				if(defined($pipes->{$name}->{stdin}->{$end}) &&
				   defined(fileno($pipes->{$name}->{stdin}->{$end}))) {
				    close($pipes->{$name}->{stdin}->{$end})
					or die sprintf("cannot close stdin %s for %s", $end, $name);
				}
			    }
			}
			delete $pipes->{$name};
		    } else {
			spawn_child($child);
		    }
		} else {
		    warning("child has no name: pid %d", $pid);
		}
	    }
	}
    }
}

=head2 alive_p

Returns truthy value iff process is still alive.

=cut

sub alive_p {
    my ($pid) = @_;
    return (defined($pid) ? kill(0, $pid) : 0);
}

=head2 validate_process

Verify a process specification is legal.

=cut

=head2 reconfigure

This function is called whenever the B<arch-daemon> process receives
the B<SIGHUP> signal. It calculates and effects the difference between
what is running and what the new contents of the configuration file
indicate should be running.

If any running processes have been removed from the configuration
file, they will be retired by sending them the SIGTERM signal, and
upon cleanup their B<STDIN>, B<STDOUT>, and B<STDERR> streams will be
closed.

If new processes are spawned, their B<STDIN> will be redirected from
B</dev/null>, unless another process has a directive to redirect their
B<STDOUT> or B<STDERR> to its name, in which case its B<STDIN> will be
redirected from that pipe. Furthermore the B<STDOUT> and B<STDERR> of
a new process will be redirected to the master log file, unless the
configuration file directs either of those to another process, in
which case each of those streams will be routed accordingly. Multiple
processes may direct their B<STDOUT> and/or B<STDERR> to another
process by specifying the target process's name in the configuration
file.

=cut

sub reconfigure {
    my ($config) = @_;

    verbose("reading config file: [%s]", $config);
    my $desired_processes = validate_processes(
	set_process_defaults(
	    decode_json(file_read($config))));

    create_pipes($desired_processes);

    info("SPAWNING CHILDREN");
    my $names = [sort keys %$desired_processes];
    debug("children: %s", encode_json([sort keys %$desired_processes]));
    # remove log from names
    foreach my $name (@$names) {
	if(defined(my $child = find_child_by_name($children, $name))) {
	    debug("%s: keep", $name);
	} else {
	    spawn_child($desired_processes->{$name});
	}
    }
    verbose("RETIRING CHILDREN");
    foreach my $pid (keys %$children) {
    	my $name = $children->{$pid}->{name};
    	if(!exists($desired_processes->{$name})) {
    	    if(defined(my $child = find_child_by_name($children, $name))) {
    		debug("%s: retire", $name);
    		$retired->{$name} = 1; # tell REAPER not to respawn this
    		kill('TERM', $pid);
    	    } else {
    		warning("reaper failed to clean up after process: %s", $name);
    		delete $children->{$pid};
    	    }
    	}
    }
}

=head2 find_child_by_name

Searches through children processes and locates the one with the name
that matches the name parameter.

=cut

sub find_child_by_name {
    my ($children,$name) = @_;
    my $pids = [keys %$children];
    my $pid = find_first($pids,
			 sub {
			     my $pid = shift;
			     my $child = $children->{$pid};
			     (defined($child) && $child->{name} eq $name)
			 });
    if(defined($pid)) {
	$children->{$pid};
    } else {
	undef;
    }
}

=head2 create_pipes

Create pipes for the log monitor and all children processes, storing
the appropriate file handles for each process io streams for use when
each process is spawned.

=cut

sub create_pipes {
    my ($procs) = @_;
    verbose("creating pipes");
    my $must_restart = [];
    my $names = [sort keys %$procs];
    debug("children: %s", encode_json([sort keys %$procs]));

    unshift(@$names, 'log');
    foreach my $name (@$names) {
	foreach my $stream (qw(stdout stderr)) {
	    my $writers = find_all($names, 
				   sub {
				       my $internal_name = shift;
				       my $recipient = $procs->{$internal_name}->{$stream};
				       (defined($recipient) && $recipient eq $name)
				   }
		);
	    if(scalar(@$writers)) {
		# debug("children %s write %s to [%s]", join(" ", map { sprintf("[%s]", $_) } @$writers), $stream, $name);
		if(!defined($pipes->{$name}->{stdin}) ||
		   !defined(fileno($pipes->{$name}->{stdin}->{read}))) {
		    debug("creating pipe for [%s] stdin", $name);
		    pipe($pipes->{$name}->{stdin}->{read}, $pipes->{$name}->{stdin}->{write})
			or die sprintf("cannot create stdin pipe for %s: [%s]\n", $name, $!);
		    select((select($pipes->{$name}->{stdin}->{write}), $| = 1)[0]); # autoflush
		}
		foreach my $writer (@$writers) {
		    debug("child [%s] setting %s to [%s]", $writer, $stream, $name);
		    $pipes->{$writer}->{$stream} = $pipes->{$name}->{stdin}->{write};
		}
	    } else {
		debug("no children write %s to [%s]", $stream, $name);
		# CANNOT RESET HERE BECAUSE NOT THROUGH LOOP YET...

		# if(defined($pipes->{$name}->{stdin}) &&
		#    defined($pipes->{$name}->{stdin}->{read}) &&
		#    defined(fileno($pipes->{$name}->{stdin}->{read}))) {
		#     # search for procs writing to this stdin
		#     #   change output to log
		#     #   add them to restart list
		#     debug("closing stdin pipe for: %s", $name);
		#     close($pipes->{$name}->{stdin}->{read});
		#     close($pipes->{$name}->{stdin}->{write});
		#     delete $pipes->{$name}->{stdin};
		# }
	    }
	}
    }
    foreach my $name (@$must_restart) {
	debug("TODO: restart if running: %s", $name);
    }
}

=head2 REAPER

Internal function to reap children processes once they have
terminated.

=cut

sub REAPER {
    local ($!,$?);
    while ((my $pid = waitpid(-1, WNOHANG)) > 0) {
	$children->{$pid}->{status} = $?;
	if(defined($children->{$pid})) {
	    debug("child reaped: pid %d: [%s]", $pid, $children->{$pid}->{name});
	} else {
	    debug("child reaped before parent started tracking it: pid %d", $pid);
	}
    }
    $SIG{CHLD} = \&REAPER;
}

=head1 AUTHOR

Karrick S. McDermott, C<< <karrick at karrick.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-ksm-daemon at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=KSM-Daemon>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc KSM::Daemon


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=KSM-Daemon>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/KSM-Daemon>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/KSM-Daemon>

=item * Search CPAN

L<http://search.cpan.org/dist/KSM-Daemon/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 Karrick S. McDermott.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of KSM::Daemon
