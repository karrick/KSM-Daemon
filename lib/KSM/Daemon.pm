package KSM::Daemon;

use utf8;
use strict;
use warnings;

use Carp;
use File::Basename ();
use POSIX ":sys_wait_h";

use KSM::Helper qw(:all);
use KSM::Logger qw(:all);

=head1 NAME

KSM::Daemon - The great new KSM::Daemon!

=head1 VERSION

Version 1.1.0

=cut

our $VERSION = '1.1.0';

=head1 SYNOPSIS

The KSM::Daemon module performs daemon management and assists with
logging for your perl programs.  It works in conjunction with
KSM::Logger.

Perhaps a little code snippet.

    use KSM::Logger qw(:all);
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
our %EXPORT_TAGS = ( 'all' => [qw(daemonize)]);
our @EXPORT_OK = (@{$EXPORT_TAGS{'all'}});

=head1 GLOBALS

There are a few module level variables to maintain state of
KSM::Daemon.

=cut

our $children = {};
our $unknown_children = {};
our $respawn = 1;
our $stdout_write;
our $stderr_write;

=head1 SUBROUTINES/METHODS

=head2 REAPER

Internal function to reap children processes once they have
terminated, and to spawn replacement processes in their place.

=cut

sub REAPER {
    my ($pid,$status,$child);
    # If a second child dies while in the signal handler caused by the
    # first death, we won't get another signal. So must loop here else
    # we will leave the unreaped child as a zombie. And the next time
    # two children die we get another zombie. And so on.
    while (($pid = waitpid(-1,WNOHANG)) > 0) {
	$status = $?;
	if(defined($child = $children->{$pid})) {
	    $child->{status} = $status;
	    $child->{ended} = time;
	    $child->{duration} = ($child->{ended} - $child->{started});
	    if($child->{status}) {
		$child->{delay} = $child->{error};
	    } else {
		$child->{delay} = $child->{restart};
	    }
	    log_termination_of_child($child);
	    delete $children->{$pid};
            spawn_child($child) if $respawn;
	} else {
	    warning("reaped unknown child: %d", $pid);
	    # NOTE: this child's pid is left in $children, and
	    # relaying signals would attempt to send a non-child the
	    # signal.
	}
    }
    if(scalar(keys %$children)) {
	$SIG{CHLD} = \&REAPER;  # still loathe SysV
    } else {
	info("all children terminated: exiting.");
	exit;
    }
}

=head2 log_termination_of_child

Log the termination of a child process, including runtime statistics
and exit conditions.

=cut

sub log_termination_of_child {
    my ($child) = @_;

    if($child->{status}) {
	warning("child (%s) (pid %d)%s terminated status code %d after %g seconds",
		$child->{name}, $child->{pid},
		($child->{status} & 127
		 ? sprintf(" received signal %d and", $child->{status} & 127)
		 : ""),
		$child->{status} >> 8, $child->{duration});
    } else {
	info('child %d (%s) terminated status code 0 after %g seconds',
	     $child->{pid}, $child->{name}, $child->{status});
    }
    $child;
}

=head2 daemonize

nThis function daemonizes your program according to Perl best practices
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
    my $status = $@;
    croak sprintf("cannot daemonize: %s\n", $status) if ($status);

    info("DAEMONIZING: %s", File::Basename::basename($0));
    daemonize_process();
    setup_signal_handlers();

    my ($stdout_read,$stderr_read);
    pipe($stdout_read, $stdout_write)
	or die error("cannot pipe: %s\n", $!);
    $stdout_write->autoflush(1);

    pipe($stderr_read, $stderr_write)
	or die error("cannot pipe: %s\n", $!);
    $stderr_write->autoflush(1);

    info("SPAWNING CHILDREN");
    foreach (@$requested_children) {
	spawn_child($_);
    }
    output_monitor($stdout_read,$stderr_read);
}

=head2 verify_children

Verify list of children process hashes is valid.

Croaks if error during validation of children hashes.

=cut

sub verify_children {
    my ($children) = @_;
    
    if(ref($children) ne 'ARRAY') {
	croak("children should be reference to array\n");
    } elsif(scalar(@$children) == 0) {
    	croak("children should have at least one child\n");
    } else {
    	verbose("VERIFYING CHILDREN");
	map {
    	    eval { verify_child($_) };
	    my $status = $@;
	    croak sprintf("cannot verify children: %s\n", $status) if($status);
	} @$children;
    }
}

=head2 verify_child

Verify arguments valid and normalize arguments for a given child hash.

Returns child hash if valid, and croaks if invalid parameters.

=cut

sub verify_child {
    my ($child) = @_;

    # croak if required arguments missing or invalid
    if(ref($child) ne 'HASH') {
	croak("child should be reference to a hash\n");
    } elsif(!defined($child->{name}) || ref($child->{name}) ne '') {
	croak("child name should be string\n");
    } elsif(defined($child->{user}) && ref($child->{user}) ne '') {
	croak("child user should be string\n");
    } elsif(ref($child->{function}) ne 'CODE') {
    	croak("child function should be a function\n");
    } elsif(defined($child->{signals}) && ref($child->{signals}) ne 'ARRAY') {
    	croak sprintf("child signals should be reference to array: [%s]\n", ref($child->{signals}));
    } elsif(defined($child->{args}) && ref($child->{args}) ne 'ARRAY') {
    	croak("child args should be reference to array\n");
    } elsif(defined($child->{restart}) && ref($child->{restart}) ne '') {
    	croak sprintf("child restart should be a scalar: [%s]\n", ref($child->{restart}));
    } elsif(defined($child->{error}) && ref($child->{error}) ne '') {
    	croak sprintf("child error should be a scalar: %s\n", ref($child->{error}));
    }
    
    # set defaults for optional arguments
    $child->{signals} = [] if(!defined($child->{signals}));
    foreach my $signal (qw(INT TERM)) {
	unshift(@{$child->{signals}}, $signal) if(!any($child->{signals}, sub { shift eq $signal }))
    }
    $child->{args} = [] if(!defined($child->{args}));
    $child->{restart} = 0 if(!defined($child->{restart}));
    $child->{error} = 0 if(!defined($child->{error}));
    $child;
}

=head2 daemonize_process

Internal function that daemonizes the process, in accordance with
guidance in 'man perlipc'.

=cut

sub daemonize_process {
    chdir '/' or die sprintf("Cannot chdir(/): %s\n", $!);

    open STDIN,'/dev/null' or die sprintf("Cannot read from /dev/null: %s\n", $!);
    open STDOUT,'>/dev/null' or die sprintf("Cannot write to /dev/null: %s\n", $!);

    defined(my $pid = fork) or die sprintf("Cannot fork: %s\n", $!);
    exit if $pid;		# parent exits
    POSIX::setsid or die sprintf("Cannot start a new session: %s\n", $!);
    open STDERR,'>&STDOUT' or die sprintf("Cannot dup stdout: %s\n", $!);
}

=head2 setup_signal_handlers

Internal function that prepares signal handlers for USR1 and TERM
signals.

=cut

sub setup_signal_handlers {
    $SIG{HUP}	= sub { send_signal_to_children('HUP') };

    $SIG{INT}	= sub { terminate_program('INT') };
    $SIG{QUIT}	= sub { terminate_program('QUIT') };

    $SIG{ILL}	= sub { terminate_program('ILL') };
    $SIG{ABRT}	= sub { terminate_program('ABRT') };
    $SIG{FPE}	= sub { terminate_program('FPE') };
    $SIG{SEGV}	= sub { terminate_program('SEGV') };
    $SIG{PIPE}	= sub { terminate_program('PIPE') };

    $SIG{ALRM}	= sub { send_signal_to_children('ALRM') };
    $SIG{TERM}	= sub { terminate_program('TERM') };
    $SIG{USR1}	= sub { send_signal_to_children('USR1') };
    $SIG{USR2}	= sub { send_signal_to_children('USR2') };
    $SIG{CHLD}	= \&REAPER;
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
    $respawn = 0;
    info("received %s signal: preparing to shut down", $sig);
    send_signal_to_children('TERM');
}

=head2 send_signal_to_children

Internal function used to relay a signal to children processes.

=cut

sub send_signal_to_children {
    my ($signal) = @_;
    foreach my $pid (keys %$children) {
	maybe_relay_signal_to_child($signal, $children->{$pid})
    }
}

=head2 maybe_relay_signal_to_child

Relays a signal to child iff child requested it.

=cut

sub maybe_relay_signal_to_child {
    my ($signal,$child) = @_;
    if(any($child->{signals}, sub { shift eq $signal })) {
	info('relaying %s signal to child %d (%s)', $signal, $child->{pid}, $child->{name});
	kill($signal, $child->{pid});
    } else {
	info('not relaying %s signal to child %d (%s)', $signal, $child->{pid}, $child->{name});
    }
}

=head2 spawn_child

Internal function that spawns a given child process, redirecting its
standard output and standard error to pipes monitored by the
&output_monitor function.

=cut

sub spawn_child {
    my ($child) = @_;

    local $SIG{ALRM} = sub { debug("received ALRM") };

    if(my $pid = fork) {
        $children->{$pid} = $child;
	$child->{pid} = $pid;
	$child->{started} = time;
        info('spawned child (%s) (pid %d)', $child->{name}, $pid);
	kill('ALRM',$pid);
    } elsif(defined $pid) {
	eval {
	    sleep; # until signal arrives
	    reset_signal_handlers();
	    $children = {};		# child has no children yet
	    $0 = $child->{name};	# attempt to set name visible by ps(1)

	    if(exists($child->{delay}) && $child->{delay}) {
		verbose('snooze: %g seconds (%s)', $child->{delay}, $child->{name});
		sleep $child->{delay};
		delete $child->{delay};
	    }

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
	    
	    open(STDOUT, '>&=', $stdout_write)
		or die sprintf("cannot redirect STDOUT: [%s]\n", $!);
	    open(STDERR, '>&=', $stderr_write)
		or die sprintf("cannot redirect STDERR: [%s]\n", $!);

	    $child->{function}->(@{$child->{args}});
	    exit;
	};
	if(my $status = $@) {
	    chomp($status);
	    error("child FAILURE: [%s]\n", $status);
	    exit(1);
	}
    } else {
        die error("cannot fork: [%s]\n", $!);
    }
}

=head2 output_monitor

Internal function that monitors two pipes, one for standard output and
one for standard input.  Data sent to standard output is redirected to
the log file in the form of an INFO message.  Data sent to standard
error is redirected to the log file in the form of an WARN message.

Because this uses the select(2) OS call to monitor two pipes, it must
use the Perl &sysread function to read from the pipe, as one cannot
mix buffered and unbuffered I/O.

=cut

sub output_monitor {
    my ($stdout_read,$stderr_read) = @_;

    info("MONITORING OUTPUT");

    my $rin = '';
    foreach ($stdout_read,$stderr_read) {
        vec($rin, fileno($_), 1) = 1;
    }
    my ($rout,$nfound,$output);
    while(1) {
        # http://perlmonks.org/?node=371720
        $nfound = select($rout=$rin, undef, undef, undef);
        next unless $nfound;

        if(vec($rout, fileno($stdout_read), 1) == 1) {
            $output = sysread_file_handle($stdout_read);
            foreach (split(/\n/, $output)) {
                info("child STDOUT: %s", $_);
            }
        }
        if(vec($rout, fileno($stderr_read), 1) == 1) {
            $output = sysread_file_handle($stderr_read);
            foreach (split(/\n/, $output)) {
                warning("child STDERR: %s", $_);
            }
        }
    }
}

=head2 sysread_file_handle

Internal function that reads from a given pipe using the OS read
function, strips any newline, and returns it to the calling function.

=cut

sub sysread_file_handle {
    my ($fh) = @_;
    my $output;
    sysread($fh, $output, 512);
    chomp($output);
    $output;
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
