##! Script for discovering United States Social Security Numbers being sent in clear
##! text in HTTP and SMTP traffic.

@load base/frameworks/notice

module SsnExposure;

export {
	## SSN exposure log ID definition.
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += { 
		Found
	};

	type Info: record {
		## When the SSN was seen.
		ts:   time    &log;
		## Unique ID for the connection.
		uid:  string  &log;
		## Connection details.
		id:   conn_id &log;
		## SSN that was discovered.
		ssn:  string  &log &optional;
		## Data that was received when the SSN was discovered.
		data: string  &log;
	};

	type StateRange: record {
		## The name of the state this range represents.
		state: string &optional;
		## Value representing the beginning of the state range.
		low: count;
		## Value representing the end of the state range.
		high: count;
	};
	
	## A file meant for the input framework to read in.  It only needs
	## to contain a list of SSNs and the SSNs should be put
	## in without any separators (e.g. 123456789).
	const ssn_file = "" &redef;

	## This is an alternate to acquiring a list of known SSNs held
	## at your business/university.  This will certainly be the quickest
	## path to results in most cases and seems to work fairly well.
	##
	## ..note: Check the following URL and set this value to what you expect 
	##         most SSNs at your site to be: http://www.mrfa.org/ssn.htm
	##         
	##         For example, a state university can probably assume that many 
	##         SSNs they hold will be for people from that state or possibly
	##         neighboring states.
	const prefixes: set[StateRange] = {} &redef;

	## If you want to avoid creating new PII logs with Bro, you can redact the 
	## ssn_exposure log with this option.  Notices are automatically and
	## unchangeably redacted.
	const redact_log = F &redef;

	## Regular expression that matches US Social Security Numbers loosely.
	## It's unlikely that you will want to change this.
	const ssn_regex = /([^0-9\-\.=\/\\%_]|^)\0?[0-6](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){4}([^0-9\-\.=\/\\%_]|$)/ &redef;

	## Separators for SSNs to assist in validation.  It's unlikely that you
	## will want to change this.
	const ssn_separators = /\..*\./ | 
	                       /\-.*\-/ | 
	                       /[:blank:].*[:blank:]/ &redef;

	## The character used for redaction to replace all numbers.
	const redaction_char = "X" &redef;

	## The number of bytes around the discovered and redacted SSN that is used 
	## as a summary in notices.
	const redaction_summary_length = 200 &redef;
}

# the internal list of "known SSNs" which is populated through the intelligence framework.
global ssn_list: set[string] = {};


type InputVal: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	add ssn_list[s];
	}

event bro_init() &priority=5
	{
	Log::create_stream(SsnExposure::LOG, [$columns=Info]);
	
	if ( ssn_file != "" )
		{
		Input::add_event([$source=ssn_file, 
		                  $name="ssn-exposure", 
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $want_record=F,
		                  $fields=InputVal,
		                  $ev=line]);
		}
	}

# This function is used for validating and notifying about SSNs in a string.
function check_ssns(c: connection, data: string): bool
	{
	local ssnps = find_all(data, ssn_regex);

	for ( ssnp in ssnps )
		{
		# Remove non-numeric character at beginning and end of string.
		ssnp = sub(ssnp, /^[^0-9]*/, "");
		ssnp = sub(ssnp, /[^0-9]*$/, "");

		if ( ssn_separators !in ssnp )
			next;

		# Remove all non-numerics
		local clean_ssnp = gsub(ssnp, /[^0-9]/, "");
		# Strip off any leading chars
		local ssn = sub_bytes(clean_ssnp, byte_len(clean_ssnp)-8, 9);

		local it_matched = F;
		if ( |prefixes| > 0 )
			{
			local ssn_prefix_test = to_count(sub_bytes(ssn, 0, 3));
			for ( prefix in prefixes )
				{
				if ( ssn_prefix_test >= prefix$low &&
				     ssn_prefix_test <= prefix$high )
					it_matched = T;
				}
			}
		
		if ( |ssn_list| > 0 && ssn in ssn_list )
			{
			it_matched = T;
			}
		
		if ( it_matched )
			{
			local parts = split_all(data, ssn_regex);
			local ssn_match = "";
			local redacted_ssn = "";
			for ( i in parts )
				{
				if ( i % 2 == 0 )
					{
					# Redact all SSN matches and save one back for 
					# finding it's location.
					ssn_match = parts[i];
					parts[i] = gsub(parts[i], /[0-9]/, redaction_char);
					redacted_ssn = parts[i];
					}
				}

			local redacted_data = join_string_array("", parts);
			local ssn_location = strstr(data, ssn_match);

			local begin = 0;
			if ( ssn_location > (redaction_summary_length/2) )
				begin = ssn_location - (redaction_summary_length/2);
			
			local byte_count = redaction_summary_length;
			if ( begin + redaction_summary_length > |redacted_data| )
				byte_count = |redacted_data| - begin;

			local trimmed_data = sub_bytes(redacted_data, begin, byte_count);

			NOTICE([$note=Found,
			        $conn=c,
			        $msg=fmt("Redacted excerpt of disclosed ssn session: %s", trimmed_data),
			        $identity=cat(c$id$orig_h,c$id$resp_h)]);

			local log: Info = [$ts=network_time(), 
			                   $uid=c$uid, $id=c$id,
			                   $ssn=(redact_log ? redacted_ssn : ssn_match),
			                   $data=(redact_log ? redacted_data : data)];

			Log::write(SsnExposure::LOG, log);

			return T;
			}
		}
		return F;
	}


event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if ( c$start_time > network_time()-10secs )
		check_ssns(c, data);
	}

event mime_segment_data(c: connection, length: count, data: string)
	{
	if ( c$start_time > network_time()-10secs )
		check_ssns(c, data);
	}

# This is used if the signature based technique is in use
function validate_ssn_match(state: signature_state, data: string): bool
	{
	# TODO: Don't handle HTTP data this way.
	if ( /^GET/ in data )
		return F;

	return check_ssns(state$conn, data);
	}