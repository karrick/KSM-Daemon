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
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'KSM-Daemon-*' },
);
