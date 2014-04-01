use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'KSM::Daemon',
    AUTHOR              => q{Karrick S. McDermott <karrick@karrick.net>},
    VERSION_FROM        => 'lib/KSM/Daemon.pm',
    ABSTRACT_FROM       => 'lib/KSM/Daemon.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    EXE_FILES => [
        'bin/arch-daemon',
    ],
    BUILD_REQUIRES => {
	'Capture::Tiny' => 0.17,
	'Test::Class' => 0,
        'Test::More' => 0,
    },
    PREREQ_PM => {
	'KSM::Helper' => '2.0.4',
	'KSM::Logger' => '2.0.0',
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'KSM-Daemon-*' },
);

sub MY::postamble {
    my $postamble = <<'MAKE_FRAG';
.PHONY: rpm

rpm:	distcheck dist
	cpan2rpm --force --no-sign $(DISTVNAME).tar.$(SUFFIX)
MAKE_FRAG

    return $postamble;
}
