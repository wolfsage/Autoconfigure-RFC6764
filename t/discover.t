use lib qw(lib);

use strict;
use warnings;

use Test::More;
use Test::Deep ':v1';
use Test::Routine;
use Test::Routine::Util;

use Try::Tiny;

use Net::Autoconfigure::RFC6764;
use Net::Autoconfigure::RFC6764::MockDNSServer;

sub basic_mocker {
  Net::Autoconfigure::RFC6764::MockDNSServer->basic_mocker(@_);
}

sub basic_mocked_autoconfigure {
  my ($ac_args, $mock_args) = @_;
  $ac_args ||= {};
  $mock_args ||= {};

  my $mock = basic_mocker($mock_args);
  my $server = $mock->as_server;
  my $ac = Net::Autoconfigure::RFC6764->new({
    %$ac_args,
    resolver => $mock->resolver_for($server),
  });

  $ac->{_mock} = $mock;
  $ac->{_server} = $server;

  return $ac;
}

test "default settings - no txt records" => sub {
  my $ac = basic_mocked_autoconfigure;

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/.well-known/caldav',
      carddav => 'https://carddav.example.net/.well-known/carddav',
    },
    "basic discover functionality looks good",
  ) or diag explain $conf;
};

test "default settings - txt records" => sub {
  my $ac = basic_mocked_autoconfigure({}, { include_txt => 1 });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/foocalsecure',
      carddav => 'https://carddav.example.net/foocardsecure',
    },
    "basic discover functionality looks good",
  ) or diag explain $conf;
};

test "caldav only - construction time" => sub {
  my $ac = basic_mocked_autoconfigure({ check_caldav => 0 });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      carddav => 'https://carddav.example.net/.well-known/carddav',
    },
    "got expected response",
  ) or diag explain $conf;
};

test "carddav only - construction time" => sub {
  my $ac = basic_mocked_autoconfigure({ check_carddav => 0 });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/.well-known/caldav',
    },
    "got expected response",
  ) or diag explain $conf;
};

test "caldav only - override" => sub {
  my $ac = basic_mocked_autoconfigure;

  my $conf = $ac->discover('test@example.net', { check_caldav => 0 });
  cmp_deeply(
    $conf,
    {
      carddav => 'https://carddav.example.net/.well-known/carddav',
    },
    "got expected response",
  ) or diag explain $conf;
};

test "carddav only - override" => sub {
  my $ac = basic_mocked_autoconfigure;

  my $conf = $ac->discover('test@example.net', { check_carddav => 0 });

  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net/.well-known/caldav',
    },
    "got expected response",
  ) or diag explain $conf;
};

test "bad email" => sub {
  my $ac = basic_mocked_autoconfigure;

  my $res = try {
    $ac->discover("foobar"); # no @domain...
  } catch {
    $_;
  };

  like(
    $res,
    qr/\QInvalid email 'foobar'? No domain part detected\E/i,
    "good error with bad email"
  );
};

test "no secure records" => sub {
  my $ac = basic_mocked_autoconfigure(
    {},
    { include_txt => 1, no_secure => 1 }
  );

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'http://caldav.example.net/foocal',
      carddav => 'http://carddav.example.net/foocard',
    },
    "good response",
  ) or diag explain $conf;
};

test "different secure port" => sub {
  my $ac = basic_mocked_autoconfigure(
    {},
    { include_txt => 1, alt_ports => 1 }
  );

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://caldav.example.net:9443/foocalsecure',
      carddav => 'https://carddav.example.net:9444/foocardsecure',
    },
    "good response",
  ) or diag explain $conf;
};

test "different non-secure port" => sub {
  my $ac = basic_mocked_autoconfigure(
    {},
    { include_txt => 1, no_secure => 1, alt_ports => 1 }
  );

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'http://caldav.example.net:8080/foocal',
      carddav => 'http://carddav.example.net:8081/foocard',
    },
    "good response",
  ) or diag explain $conf;
};

test "srv sorts properly" => sub {
  my $mock = Net::Autoconfigure::RFC6764::MockDNSServer->new;

  # Lowest prio, lowest weight, won't get picked
  $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 1,
      target   => 'notpicked1.example.net',
      port     => 443,
  });

  # Lowest prio, highest weight, will get picked
  $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 10,
      target   => 'picked.example.net',
      port     => 443,
  });

  # Lowest prio, mid weight, won't get picked
  $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 5,
      target   => 'notpicked2.example.net',
      port     => 443,
  });

  # Higher prio, won't get picked
  $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'srv',
      priority => 2,
      weight   => 5,
      target   => 'notpicked3.example.net',
      port     => 443,
  });

  my $server = $mock->as_server;
  my $ac = Net::Autoconfigure::RFC6764->new({
    resolver => Net::DNS::Resolver->new(
      nameserver => [ '127.0.0.1' ],
      port       => $server->port,
    ),
  });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://picked.example.net/.well-known/caldav',
    },
    "good response",
  ) or diag explain $conf;
};

test "timeout" => sub {
  my $ac = basic_mocked_autoconfigure(
    { timeout => 3 },
    { include_txt => 1, sleep_after_seconds => 5 },
  );

  my $conf = $ac->discover('test@example.net');

  # We'll get one answer and then nothing before the timeout.
  # That one answer should be the non-secure caldav SRV record
  # since _caldav. sorts before _caldavs. and txt sorts before
  # srv and the lookup query order is deterministic
  cmp_deeply(
    $conf,
    {
      caldav  => 'http://caldav.example.net/.well-known/caldav',
    },
    "good response",
  ) or diag explain $conf;
};

test "secure only - construction time" => sub {
  my $mock = Net::Autoconfigure::RFC6764::MockDNSServer->new;

  # Secure caldav, but no secure carddav. Should only find caldav
  $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 1,
      target   => 'secure.caldav.example.net',
      port     => 443,
  });

  $mock->add({
      host     => '_caldav._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 10,
      target   => 'insecure.caldav.example.net',
      port     => 80,
  });

  $mock->add({
      host     => '_carddav._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 5,
      target   => 'insecure.carddav.example.net',
      port     => 80,
  });

  my $server = $mock->as_server;
  my $ac = Net::Autoconfigure::RFC6764->new({
    resolver => Net::DNS::Resolver->new(
      nameserver => [ '127.0.0.1' ],
      port       => $server->port,
    ),
    secure_only => 1,
  });

  my $conf = $ac->discover('test@example.net');
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://secure.caldav.example.net/.well-known/caldav',
    },
    "with secure only and no secure options, no results",
  ) or diag explain $conf;
};

test "secure only - override" => sub {
  my $mock = Net::Autoconfigure::RFC6764::MockDNSServer->new;

  # Secure caldav, but no secure carddav. Should only find caldav
  $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 1,
      target   => 'secure.caldav.example.net',
      port     => 443,
  });

  $mock->add({
      host     => '_caldav._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 10,
      target   => 'insecure.caldav.example.net',
      port     => 80,
  });

  $mock->add({
      host     => '_carddav._tcp.example.net',
      type     => 'srv',
      priority => 1,
      weight   => 5,
      target   => 'insecure.carddav.example.net',
      port     => 80,
  });

  my $server = $mock->as_server;
  my $ac = Net::Autoconfigure::RFC6764->new({
    resolver => Net::DNS::Resolver->new(
      nameserver => [ '127.0.0.1' ],
      port       => $server->port,
    ),
  });

  my $conf = $ac->discover('test@example.net', { secure_only => 1 });
  cmp_deeply(
    $conf,
    {
      caldav  => 'https://secure.caldav.example.net/.well-known/caldav',
    },
    "with secure only and no secure options, no results",
  ) or diag explain $conf;
};

run_me;
done_testing;
