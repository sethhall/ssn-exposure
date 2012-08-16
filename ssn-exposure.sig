signature ssn-match {
	ip-proto == tcp
	payload /.*([^0-9\-\.=\/\\%_]|^)\0?[0-6](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){4}([^0-9\-\.=\/\\%_]|$)/
	eval SsnExposure::validate_ssn_match
}