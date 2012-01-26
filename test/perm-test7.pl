#!/usr/bin/perl -w

use strict;
use PVE::Tools;
use PVE::AccessControl;
use PVE::RPCEnvironment;
use Getopt::Long;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $cfgfn = "test7.cfg";
$rpcenv->init_request(userconfig => $cfgfn);

sub check_roles {
    my ($user, $path, $expected_result) = @_;

    my @ra = $rpcenv->roles($user, $path);
    my $res = join(',', sort @ra);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
	if $res ne $expected_result;

    print "ROLES:$path:$user:$res\n";
}


check_roles('User1@pve', '/vms', 'Role1');
check_roles('User1@pve', '/vms/200', 'Role1');
check_roles('User1@pve', '/vms/100', 'NoAccess');

print "all tests passed\n";

exit (0);