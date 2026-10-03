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

## iOS / macOS (darwinv3 Database)

Based on the `darwinv3` datasource implementation in the codebase (`wccontact_new2.db` -> `WCContact` table):
- The short display name remark is mapped to the `m_nsRemark` column.
- *Note: Further inspection of the iOS database schema would be required to confirm which specific column stores the extended description equivalent to `Reserved6`.*

## V4 Database Structure

In the newer v4 database structure (found in newer Mac/PC versions):
- Database: `contact.db`
- Table: `contact`
- The short display name is mapped to the `remark` column.
