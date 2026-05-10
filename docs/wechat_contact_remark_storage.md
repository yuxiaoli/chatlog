# WeChat Contact Remark Field Storage

## Overview
This document summarizes the findings regarding where WeChat stores the contact "Remark" information. Specifically, it distinguishes between the short "Remark" (Display Name) and the longer descriptive "Remark" (Profile Description) that appears in a contact's profile.

## Windows (v3 Database)

In the Windows v3 database structure, the data is stored in the `MicroMsg.db` database file within the `Contact` table.

Interestingly, the UI terminology does not perfectly match the database column names:

| UI Field | Database Column | Description | Example Value (from screenshot) |
| :--- | :--- | :--- | :--- |
| **Alias / WeChat ID** | `Alias` | The user's unique WeChat ID | `xiaoruizhao-` |
| **NickName** | `NickName` | The user's original nickname | `晓晓` |
| **Remark (Display Name)** | `Remark` | The custom name you set for the contact | `无理取闹的大瑞` |
| **Remark (Description)** | `Reserved6` | The long descriptive text in the profile | `生日：阴历1994年11月18日（冬月18）` |

### Key Finding
If you are looking for the long descriptive text (e.g., phone numbers, birthdays, or extra notes) added to a contact's profile, **do not look in the `Remark` column**. Instead, query the `Reserved6` column in the `Contact` table.

## Contact Tags / Labels (Windows v3)

Tags (also known as Labels in the database) applied to contacts are managed via a relational structure in the `MicroMsg.db` database:

1. **Tag Definitions (`ContactLabel` table)**
   - The `ContactLabel` table stores all created tags.
   - **`LabelId`**: The unique numeric ID of the tag.
   - **`LabelName`**: The text name of the tag (e.g., "Shanghai", "Family", "hide_their_moments").

2. **Contact Tag Mapping (`Contact` table)**
   - In the `Contact` table, the **`LabelIDList`** column stores the tags associated with each contact.
   - It is formatted as a comma-separated string of `LabelId` values (e.g., `3,5`).

To retrieve a contact's tags, you would look up the IDs in `LabelIDList` against the `LabelId` in the `ContactLabel` table.

## Other Profile Fields (Windows v3)

Additional profile fields such as "What's Up" (Signature), "From" (Add Scene), and others are stored in the **`ExtraBuf`** column of the `Contact` table. This column contains a binary TLV (Type-Length-Value) encoded protobuf-like structure. 

By parsing the `ExtraBuf` binary blob, we can identify specific fields using their Hex IDs:

| UI Field | ExtraBuf TLV ID | Data Type | Example Value / Meaning |
| :--- | :--- | :--- | :--- |
| **What's Up** (Signature) | `46cf10c4` | String (UTF-16LE) | `碰巧遇到你` |
| **From** (Add Scene) | `4d6c4570` | Int32 | `30` (Enum for "Scan QR Code") |
| **Country** | `a4d9024a` | String (UTF-16LE) | `HK` |
| **City** | `e2eaa8d1` | String (UTF-16LE) | `Yau Tsim Mong` |

*Note: The **"Add time"** field (e.g., `2025/9`) shown in iOS client profiles does not appear to be stored or synced locally within the Windows `MicroMsg.db` database.*

## iOS / macOS (darwinv3 Database)

Based on the `darwinv3` datasource implementation in the codebase (`wccontact_new2.db` -> `WCContact` table):
- The short display name remark is mapped to the `m_nsRemark` column.
- *Note: Further inspection of the iOS database schema would be required to confirm which specific column stores the extended description equivalent to `Reserved6`.*

## V4 Database Structure

In the newer v4 database structure (found in newer Mac/PC versions):
- Database: `contact.db`
- Table: `contact`
- The short display name is mapped to the `remark` column.
