package Autoconfigure::RFC6764::MockDNSServer;

use Moose;
use MooseX::StrictConstructor;

use namespace::autoclean;

use Carp qw(croak);
use Storable qw(dclone);
use Try::Tiny;
use Test::TCP;
use Net::DNS;

has matchers => (
  is => 'ro',
  isa => 'HashRef',
  default => sub { {} },
);

sub reset {
  shift->{matchers} = {};
}

sub resolver_for {
  my ($self, $server) = @_;

  return Net::DNS::Resolver->new(
    nameservers => [ '127.0.0.1' ],
    port        => $server->port,
  );
}

sub as_server {
  my ($self) = @_;

  return Test::TCP->new(
    listen => 1,
    proto  => 'udp',
    code => sub {
      my $socket = shift;
      while (1) {
        $socket->recv(my $data, 65535);
        my $packet = Net::DNS::Packet->new(\$data);
        $socket->send($self->query_handler($packet));
      }
    }
  );
}

sub add {
  my ($self, $args) = @_;
  my $host = delete($args->{host}) // croak("host required");
  my $type = delete($args->{type}) // croak("type required");
  my $class = delete($args->{class}) // "IN";

  my $rr = try {
    Net::DNS::RR->new(
      name => $host,
      type => $type,
      %$args
    );
  } catch {
    croak("Failed to create a Net::DNS::RR object: $_");
  };

  push @{ $self->matchers->{lc $host}{lc $class}{lc $type} }, $rr;

  return $rr;
}

sub query_handler {
  my ($self, $query_packet) = @_;

  my ($question) = $query_packet->question;

  my $host = $question->qname;
  my $type = $question->qtype;
  my $class = $question->qclass;

  my $rrs = $self->matchers->{lc $host}{lc $class}{lc $type} || [];
  my $packet = $query_packet->reply;

  $packet->push(answer => dclone($_)) for @$rrs;

  return $packet->data;
}

sub basic_mocker {
  my ($class, $opt) = @_;

  my $mock = __PACKAGE__->new;

  $mock->add({
    host     => '_caldavs._tcp.example.net',
    type     => 'srv',
    priority => 1,
    weight   => 1,
    target   => 'caldav.example.net',
    port     => 443,
  });
  $mock->add({
    host     => '_caldav._tcp.example.net',
    type     => 'srv',
    priority => 1,
    weight   => 1,
    target   => 'caldav.example.net',
    port     => 80,
  });

  $mock->add({
    host     => '_carddavs._tcp.example.net',
    type     => 'srv',
    priority => 1,
    weight   => 1,
    target   => 'carddav.example.net',
    port     => 443,
  });
  $mock->add({
    host     => '_carddav._tcp.example.net',
    type     => 'srv',
    priority => 1,
    weight   => 1,
    target   => 'carddav.example.net',
    port     => 80,
  });

  if ($opt->{include_txt}) {
    $mock->add({
      host     => '_caldavs._tcp.example.net',
      type     => 'txt',
      txtdata  => [ "txtversion=1", "path=/foocalsecure" ],
    });
    $mock->add({
      host     => '_caldav._tcp.example.net',
      type     => 'txt',
      txtdata  => [ "txtversion=1", "path=/foocal" ],
    });

    $mock->add({
      host     => '_carddavs._tcp.example.net',
      type     => 'txt',
      txtdata  => [ "txtversion=1", "path=/foocardsecure" ],
    });
    $mock->add({
      host     => '_carddav._tcp.example.net',
      type     => 'txt',
      txtdata  => [ "txtversion=1", "path=/foocard" ],
    });
  }

  return $mock;
}

1;
