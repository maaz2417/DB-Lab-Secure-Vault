import os
import csv
from db import get_connection

# Resolve CSV directory dynamically relative to this script location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_DIR = os.path.join(BASE_DIR, 'CSV')

def import_csv_to_table(cursor, filename, table_name, columns, boolean_indices=None):
    filepath = os.path.join(CSV_DIR, filename)
    if not os.path.exists(filepath):
        print(f"File {filepath} not found, skipping.")
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader) # Skip header row
        
        # Build query
        col_names = ", ".join(columns)
        placeholders = ", ".join(["%s"] * len(columns))
        query = f"INSERT INTO {table_name} ({col_names}) VALUES ({placeholders})"
        
        count = 0
        for row in reader:
            if not row:
                continue
            
            # Map empty values to None (NULL)
            parsed_row = []
            for i, val in enumerate(row):
                if val == "":
                    parsed_row.append(None)
                elif boolean_indices and i in boolean_indices:
                    # Convert TRUE/FALSE or 1/0
                    parsed_row.append(val.strip().upper() in ('TRUE', '1'))
                else:
                    parsed_row.append(val)
            
            # Execute insert
            cursor.execute(query, parsed_row)
            count += 1
            
        print(f"Successfully imported {count} rows into `{table_name}`.")

def main():
    print(f"Resolving synthetic data from: {CSV_DIR}")
    print("Connecting to MySQL Database...")
    conn = get_connection()
    cur = conn.cursor()
    
    print("Disabling foreign key checks for table truncate and seed...")
    cur.execute("SET FOREIGN_KEY_CHECKS = 0;")
    
    # Truncate tables to ensure a clean seed
    tables = [
        'audit_log', 'bank_credentials', 'password_history', 'sessions', 
        'failed_login_attempts', 'user_preferences', 'vault', 'credential_types', 'users'
    ]
    for table in tables:
        cur.execute(f"TRUNCATE TABLE {table};")
        print(f"Truncated `{table}`.")
        
    print("Seeding database tables...")
    
    # 1. users
    import_csv_to_table(
        cur, 'users.csv', 'users', 
        ['user_id', 'username', 'master_password_hash', 'created_at']
    )
    
    # 2. credential_types
    import_csv_to_table(
        cur, 'credential_types.csv', 'credential_types',
        ['type_id', 'type_name', 'security_level', 'requires_reauth', 'clipboard_timeout', 'description'],
        boolean_indices={3} # requires_reauth
    )
    
    # 3. vault
    import_csv_to_table(
        cur, 'vault.csv', 'vault',
        ['vault_id', 'user_id', 'type_id', 'site_name', 'username', 'encrypted_password', 'notes', 'last_updated', 'created_at']
    )
    
    # 4. bank_credentials
    import_csv_to_table(
        cur, 'bank_credentials.csv', 'bank_credentials',
        ['bank_id', 'vault_id', 'bank_name', 'account_number_encrypted', 'card_last_four', 'account_type', 'pin_encrypted', 'created_at']
    )
    
    # 5. failed_login_attempts
    import_csv_to_table(
        cur, 'failed_login_attempts.csv', 'failed_login_attempts',
        ['attempt_id', 'user_id', 'attempted_at', 'ip_address']
    )
    
    # 6. password_history
    import_csv_to_table(
        cur, 'password_history.csv', 'password_history',
        ['history_id', 'vault_id', 'encrypted_password', 'changed_at']
    )
    
    # 7. user_preferences
    import_csv_to_table(
        cur, 'user_preferences.csv', 'user_preferences',
        ['pref_id', 'user_id', 'auto_logout_minutes', 'clipboard_clear_seconds', 'theme', 'default_security_level', 'created_at']
    )
    
    # 8. sessions
    import_csv_to_table(
        cur, 'sessions.csv', 'sessions',
        ['session_id', 'user_id', 'session_token', 'created_at', 'expires_at']
    )
    
    # 9. audit_log
    import_csv_to_table(
        cur, 'audit_log.csv', 'audit_log',
        ['log_id', 'user_id', 'vault_id', 'action', 'action_time']
    )
    
    print("Re-enabling foreign key checks...")
    cur.execute("SET FOREIGN_KEY_CHECKS = 1;")
    
    conn.commit()
    cur.close()
    conn.close()
    print("Database seeding completed successfully!")

if __name__ == '__main__':
    main()
