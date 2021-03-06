package PVE::CLI::pveum;

use strict;
use warnings;
use Getopt::Long;
use PVE::Tools qw(run_command);
use PVE::Cluster;
use PVE::SafeSyslog;
use PVE::AccessControl;
use File::Path qw(make_path remove_tree);
use Term::ReadLine;
use PVE::INotify;
use PVE::RPCEnvironment;
use PVE::API2::User;
use PVE::API2::Group;
use PVE::API2::Role;
use PVE::API2::ACL;
use PVE::API2::AccessControl;
use PVE::JSONSchema qw(get_standard_option);
use PVE::CLIHandler;

use base qw(PVE::CLIHandler);

sub read_password {
    # return $ENV{PVE_PW_TICKET} if defined($ENV{PVE_PW_TICKET});

    my $term = new Term::ReadLine ('pveum');
    my $attribs = $term->Attribs;
    $attribs->{redisplay_function} = $attribs->{shadow_redisplay};
    my $input = $term->readline('Enter new password: ');
    my $conf = $term->readline('Retype new password: ');
    die "Passwords do not match.\n" if ($input ne $conf);
    return $input;
}

our $cmddef = {
    ticket => [ 'PVE::API2::AccessControl', 'create_ticket', ['username'], undef,
		sub {
		    my ($res) = @_;
		    print "$res->{ticket}\n";
		}],

    passwd => [ 'PVE::API2::AccessControl', 'change_passsword', ['userid'] ],

    useradd => [ 'PVE::API2::User', 'create_user', ['userid'] ],
    usermod => [ 'PVE::API2::User', 'update_user', ['userid'] ],
    userdel => [ 'PVE::API2::User', 'delete_user', ['userid'] ],

    groupadd => [ 'PVE::API2::Group', 'create_group', ['groupid'] ],
    groupmod => [ 'PVE::API2::Group', 'update_group', ['groupid'] ],
    groupdel => [ 'PVE::API2::Group', 'delete_group', ['groupid'] ],

    roleadd => [ 'PVE::API2::Role', 'create_role', ['roleid'] ],
    rolemod => [ 'PVE::API2::Role', 'update_role', ['roleid'] ],
    roledel => [ 'PVE::API2::Role', 'delete_role', ['roleid'] ],

    aclmod => [ 'PVE::API2::ACL', 'update_acl', ['path'], { delete => 0 }],
    acldel => [ 'PVE::API2::ACL', 'update_acl', ['path'], { delete => 1 }],
};

1;

__END__

=head1 NAME

pveum - PVE User Manager

=head1 DESCRIPTION

Tools to manage PVE users, groups, roles and permissions. Modifying roles and permissions is complex and usually easier to handle using the GUI. So the command line interface is mainly provided for scripting purposes. 

=head1 SYNOPSIS

=include synopsis

=include pve_copyright
