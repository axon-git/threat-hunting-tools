-- This query detects API calls that was invoked by a user agent known to be affiliated with attacking tools
-- The query uses Hunter's Cloudtrail Event Statistics Scheme
SELECT
    SOURCE_IP_ADDRESS AS ipAddress,
    USER_AGENT AS userAgent,
    COUNT(*) AS occurrenceCount
FROM
    INVESTIGATION.CLOUDTRAIL_EVENT_STATISTICS
WHERE
    (
        
        USER_AGENT ILIKE '%kali linux%' OR
        USER_AGENT ILIKE '%kali%-686%' OR
        USER_AGENT ILIKE '%kali%-amd64%' OR
        USER_AGENT ILIKE '%parrot-686%' OR
        USER_AGENT ILIKE '%parrot-amd64%' OR
        USER_AGENT ILIKE '%Hackintosh%' OR
        USER_AGENT ILIKE '%backbox%' OR
        USER_AGENT ILIKE '%blackarch%' OR
        USER_AGENT ILIKE '%Scout Suite%' OR
        USER_AGENT ILIKE '%trailblazer%' OR
        USER_AGENT ILIKE '%trufflehog%' OR
        USER_AGENT ILIKE '%blackarch%'

    )
    AND START_TIME > current_timestamp - interval '90d'
GROUP BY
    SOURCE_IP_ADDRESS,
    USER_AGENT;
