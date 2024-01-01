-- target process running HTA
SELECT DISTINCT
       EVENT_TIME,
       INITIATING_PROCESS_NAME,
       TARGET_PROCESS_COMMANDLINE,
       TARGET_PROCESS_UID
FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
WHERE DEVICE_PLATFORM = 'WINDOWS'
AND EVENT_TIME >= CURRENT_TIMESTAMP - INTERVAL '30 days'
-- mandatory filter
AND (LOWER(TARGET_PROCESS_NAME) = 'mshta.exe' OR LOWER(TARGET_PROCESS_COMMANDLINE) LIKE '%rundll%mshtml%')
-- possible filters
AND TARGET_PROCESS_COMMANDLINE ILIKE ANY ('%http%', '%ActiveXObject%', '%wscript%', '%users\\public%')
LIMIT 1000;


-- initiating-process by mshta.exe
SELECT DISTINCT
       EVENT_TIME, 
       INITIATING_PROCESS_NAME, 
       TARGET_PROCESS_COMMANDLINE,
       TARGET_PROCESS_UID
FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
WHERE DEVICE_PLATFORM = 'WINDOWS'
AND EVENT_TIME >= CURRENT_TIMESTAMP - INTERVAL '30 days'
-- mandatory filters
AND (LOWER(INITIATING_PROCESS_NAME) = 'mshta.exe' OR LOWER(INITIATING_PROCESS_COMMANDLINE) LIKE '%rundll%mshtml%')
-- possible filters
AND INITIATING_PROCESS_COMMANDLINE ILIKE ANY ('%http%', '%ActiveXObject%', '%wscript%', '%users\\public%')
LIMIT 1000;


-- network connections by mshta.exe
SELECT EVENT_TIME,
       INITIATING_PROCESS_COMMANDLINE,
       REMOTE_IP,
       REMOTE_PORT,
       DOMAIN,
       IS_INBOUND
FROM INVESTIGATION.EDR_NETWORK_EVENTS
WHERE DEVICE_PLATFORM = 'WINDOWS'
AND EVENT_TIME >= CURRENT_TIMESTAMP - INTERVAL '30 days'
-- mandatory filters
AND (LOWER(INITIATING_PROCESS_NAME) = 'mshta.exe' OR LOWER(INITIATING_PROCESS_COMMANDLINE) LIKE '%rundll%mshtml%')
-- possible filters
AND INITIATING_PROCESS_COMMANDLINE ILIKE ANY ('%http%', '%ActiveXObject%', '%wscript%', '%users\\public%')
LIMIT 1000;


-- file activities by mshta.exe
SELECT EVENT_TIME,
       INITIATING_PROCESS_COMMANDLINE,
       TARGET_FILE_ACTION,
       TARGET_FILE_PATH
FROM INVESTIGATION.EDR_FILE_EVENTS
WHERE DEVICE_PLATFORM = 'WINDOWS'
AND EVENT_TIME >= CURRENT_TIMESTAMP - INTERVAL '30 days'
-- mandatory filters
AND (LOWER(INITIATING_PROCESS_NAME) = 'mshta.exe' OR LOWER(INITIATING_PROCESS_COMMANDLINE) LIKE '%rundll%mshtml%')
-- possible filters
AND INITIATING_PROCESS_COMMANDLINE ILIKE ANY ('%http%', '%ActiveXObject%', '%wscript%', '%users\\public%')
LIMIT 1000;
