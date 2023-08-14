-- The query searches for a UAC bypass method that changes the value of HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin to 0 (=Elevate without prompting)
-- This activity was observed by the team in a recent InfoStealer campaign targeting Mexico (August 2023)
-- The query can be adjusted to the preferred EDR solution
with UAC_BYPASS_REG_KEY_MODIFICATIONS AS (
    SELECT DISTINCT
    EVENT_TIME,
    AID,
    EVENT_NAME,
    REGISTRY_KEY,
    REGISTRY_VALUE_NAME,
    REGISTRY_STR_VALUE_DATA,
    REGISTRY_INT_VALUE_DATA,
    REGISTRY_OPERATION_TYPE,
                    INITIATING_PROCESS_ID
FROM EDR_RAW_DATA
WHERE EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '30d'
    AND LOWER(EVENT_NAME) LIKE '%reg%update%' -- Modify with the relevant EDR event name
    AND REGISTRY_KEY ILIKE '%\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
    AND REGISTRY_VALUE_NAME = 'ConsentPromptBehaviorAdmin'
    AND REGISTRY_OPERATION_TYPE = '1' -- REG_SET_VALUE
    AND REGISTRY_INT_VALUE_DATA = 0   -- Elevate without prompting
),
-- All process creation events - Hunters' unified scheme
PROCESS_CREATIONS AS (
    SELECT
        EVENT_TIME,
        AGENT_ID,
        TARGET_PROCESS_COMMANDLINE,
        TARGET_PROCESS_HASH_SHA256
        TARGET_PROCESS_HASH,
           TARGET_PROCESS_UID
    FROM INVESTIGATION.EDR_PROCESS_CREATION_EVENTS
    WHERE
        EVENT_TIME > CURRENT_TIMESTAMP - INTERVAL '30d'
)
SELECT UAC_BYPASS_REG_KEY_MODIFICATIONS.*, INITIATING_PROC.TARGET_PROCESS_COMMANDLINE INITIATING_PROCESS_COMMAND_LINE, INITIATING_PROC.TARGET_PROCESS_HASH INITIATING_PROCESS_HASH
FROM UAC_BYPASS_REG_KEY_MODIFICATIONS LEFT JOIN
    PROCESS_CREATIONS INITIATING_PROC
ON
    -- Process responsible for the UAC bypass registry modification
    INITIATING_PROC.AGENT_ID = UAC_BYPASS_REG_KEY_MODIFICATIONS.AID
    AND INITIATING_PROC.TARGET_PROCESS_UID = UAC_BYPASS_REG_KEY_MODIFICATIONS.INITIATING_PROCESS_ID
order by EVENT_TIME asc
