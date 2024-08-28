#!/usr/bin/perl
use strict;
use warnings;
use Digest::SHA qw(sha512_hex hmac_sha512_hex);
use File::Basename;
use IO::Handle;
use URI::Escape qw(uri_unescape);

# Configuration
my $CONFIG_STORE_DIR = '/tmp';
my $CONFIG_SECRET    = '2qxjsdNXYnJbPke81tqRxYwfK6EAimwgZFZ5Pn';
my $CONFIG_CHUNK_SIZE = 4096;
my $LOG_FILE = '/logs/uploader.log';

# Open log file
open my $log_fh, '>>', $LOG_FILE or die "Cannot open log file: $!";
sub log_message {
    my ($message) = @_;
    my $timestamp = localtime();
    print $log_fh "[$timestamp] $message\n";
}

# Configuration
log_message("Starting.........");

my $query_string = $ENV{'QUERY_STRING'} || '';
$query_string = uri_unescape($query_string);
my %params = map { split(/=/, $_) } $query_string;

my $upload_file_name = $ENV{'REQUEST_URI'};
$upload_file_name = uri_unescape($upload_file_name);
$upload_file_name =~ s/\?v2=.*//;
$upload_file_name =~ s{^/}{};
my $store_file_name = "$CONFIG_STORE_DIR/store-" . sha512_hex($upload_file_name);
my $request_method = $ENV{'REQUEST_METHOD'};

print "Access-Control-Allow-Methods: GET, PUT, OPTIONS\r\n";

if ($params{'v2'} && $request_method eq 'PUT') {
    log_message("Processing PUT request");

    # Set CORS headers
    print "Connection: Keep-Alive\r\n";
    print "Access-Control-Allow-Headers: Content-Type\r\n";
    print "Content-Type: text/plain\r\n";
    print "Access-Control-Max-Age: 7200\r\n";
    print "Access-Control-Allow-Origin: *\r\n";
    print "\r\n";  # End of headers

    my $upload_file_size = $ENV{'CONTENT_LENGTH'};
    my $upload_token = $params{'v2'};
    my $upload_file_type = $ENV{'CONTENT_TYPE'} || 'application/octet-stream';

    # Validate content-type length
    if (length($upload_file_type) > 255) {
        log_message("Invalid content-type length: $upload_file_type");
        print "Status: 400 Bad Request\r\n";
        exit;
    }

    my $calculated_token = hmac_sha512_hex("$upload_file_name\0$upload_file_size\0$upload_file_type", $CONFIG_SECRET);
    if ($upload_token ne $calculated_token) {
        log_message("Token mismatch: calculated $calculated_token got $upload_token");
        print "Status: 403 Forbidden\r\n";
        exit;
    }
    
    # Open a file for writing
    open my $store_file, '>:raw', $store_file_name or do {
        log_message("Cannot open file for writing: $store_file_name");
        print "Status: 409 Conflict\r\n";
        exit;
    };
    $store_file->autoflush(1);

    # PUT data comes in on the stdin stream
    my $incoming_data;
    binmode(STDIN);
    while (read(STDIN, $incoming_data, $CONFIG_CHUNK_SIZE)) {
        binmode($incoming_data);
        binmode($store_file);
        print $store_file $incoming_data;
    }
    # Close the streams
    close $store_file;
    
    my $size = -s $store_file_name;
    if ($size ne $upload_file_size) {
        log_message("File size mismatch: calculated $size got $upload_file_size for $store_file_name");
        print "Status: 403 Forbidden\r\n";
        exit;
    }

    open my $type_file, '>', "$store_file_name-type" or do {
        log_message("Cannot open type file for writing: $store_file_name-type");
        die "Cannot open type file: $!";
    };
    print $type_file $upload_file_type;
    close $type_file;

    log_message("File uploaded successfully: $store_file_name Size: $size Actual_Size: $upload_file_size");
    print "Status: 201 Created\r\n";
    exit;
} elsif ($request_method eq 'GET' || $request_method eq 'HEAD') {
    log_message("Processing GET/HEAD request");

    if (-e $store_file_name) {
        open my $type_file, '<', "$store_file_name-type" or do {
            log_message("Type file not found: $store_file_name-type");
            print "Status: 404 Not Found\r\n";
            print "Content-Type: text/plain\r\n\r\n";
            exit;
        };
        my $mime_type = <$type_file>;
        chomp $mime_type;
        close $type_file;

        $mime_type ||= 'application/octet-stream';
        my $size = -s $store_file_name;
        print "Content-Length: $size\r\n";
        print "Connection: Keep-Alive\r\n";
        print "Access-Control-Max-Age: 7200\r\n";
        print "Access-Control-Allow-Headers: Content-Type\r\n";
        print "Content-Type: $mime_type\r\n";
        print "Content-Disposition: inline\r\n";
        print "Access-Control-Allow-Origin: *\r\n";
        print "Content-Security-Policy: default-src 'none'\r\n";
        print "X-Content-Security-Policy: default-src 'none'\r\n";
        print "X-WebKit-CSP: default-src 'none'\r\n";
        print "\r\n";

        if ($request_method ne 'HEAD') {
            open my $file, '<', $store_file_name or do {
                log_message("Cannot open file for reading: $store_file_name");
                die "Cannot open file: $!";
            };
            binmode STDOUT;
            while (my $line = <$file>) {
                print $line;
            }
            close $file;
        }
    } else {
        log_message("File not found: $store_file_name");
        print "Status: 404 Not Found\r\n";
        print "Content-Type: text/plain\r\n\r\n";
    }
} elsif ($request_method eq 'OPTIONS') {
    log_message("Processing OPTIONS request");
    exit;
} else {
    log_message("Unsupported request method: $request_method");
    print "Status: 400 Bad Request\r\n";
    print "Content-Type: text/plain\r\n\r\n";
}

# Close log file
close $log_fh;
exit;

