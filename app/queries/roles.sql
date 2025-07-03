SELECT
(
    SELECT STUFF((
        SELECT ',' + CAST(UR.Role_ID AS VARCHAR)
        FROM dp_User_Roles UR
        LEFT JOIN dp_Users U ON U.User_ID = UR.User_ID
        WHERE U.User_GUID = @guid
        FOR XML PATH('')
    ), 1, 1, '')
) AS user_roles,
(
    SELECT STUFF((
        SELECT ',' + CAST(UUG.User_Group_ID AS VARCHAR)
        FROM dp_User_User_Groups UUG
        LEFT JOIN dp_Users U ON U.User_ID = UUG.User_ID
        WHERE U.User_GUID = @guid
        FOR XML PATH('')
    ), 1, 1, '')
) AS user_groups