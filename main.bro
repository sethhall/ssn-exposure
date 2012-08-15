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
		ssn:  string  &log;
		## Data that was received when the SSN was discovered.
		data: string  &log;
	};
	
	## You must redef this variable with a normalized list of SSNs.
	## Example for redefining this variable... (huge sets are handled easily)
	const org_list: set[string] &redef;

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
	const prefixes = {
		[$state="Ohio",         $low=268, $high=302],
		[$state="Pennsylvania", $low=159, $high=211],
		[$state="Indiana",      $low=303, $high=317],
		[$state="West Virginia",$low=233, $high=236],
		[$state="Michigan",     $low=362, $high=386],
	} &redef;

	## Regular expression that matches US Social Security Numbers loosely.
	## It's unlikely that you will want to change this.
	const ssn_regex = /([^0-9]|^)\0?[0-6](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){4}([^0-9]|$)/ &redef;

	## Separators for SSNs to assist in validation.  It's unlikely that you
	## will want to change this.
	const ssn_separators = /\..*\./ | 
	                       /\-.*\-/ | 
	                       /[:blank:].*[:blank:]/ &redef;
}

event bro_init() &priority=5
	{
	Log::create_stream(SsnExposure::LOG, [$columns=Info]);
	}

# This function is used for validating and notifying about SSNs in a string.
function check_ssns(c: connection, data: string): bool
	{
	local ssnps = find_all(data, ssn_regex);

	for ( ssnp in ssnps )
		{
		# Remove non-numeric character at beginning and end of string.
		ssnp = sub(ssnp, /^[^0-9]/, "");
		ssnp = sub(ssnp, /[^0-9]$/, "");

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
		
		if ( |org_list| > 0 && ssn in org_list )
			{
			it_matched = T;
			}
		
		if ( it_matched )
			{
			NOTICE([$note=Found,
			        $conn=c,
			        $msg=fmt("Contents of disclosed ssn session: %s", data),
			        $sub=ssn]);

			local log: Info = [$ts=network_time(), 
			                   $uid=c$uid, $id=c$id,
			                   $ssn=ssn, $data=data];
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