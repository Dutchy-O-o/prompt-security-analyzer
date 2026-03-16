#!/usr/bin/env python3
"""Reset database - remove all old data"""
import os
import sqlite3
from pathlib import Path

DB_PATH = "security_results.db"

print("\n" + "="*60)
print("DATABASE RESET TOOL")
print("="*60)

if os.path.exists(DB_PATH):
    print(f"\n📊 Database found: {DB_PATH}")
    
    # Show database size
    size = os.path.getsize(DB_PATH) / 1024  # KB
    print(f"📈 Current size: {size:.2f} KB")
    
    # Count records
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print(f"\n📋 Tables in database:")
        total_records = 0
        for (table,) in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"   • {table}: {count} records")
            total_records += count
        
        conn.close()
        
        print(f"\n📊 Total records: {total_records}")
        
        # Ask for confirmation
        response = input("\n⚠️  Delete all data? (yes/no): ").strip().lower()
        
        if response == 'yes':
            os.remove(DB_PATH)
            print("\n✓ Database deleted successfully!")
            print("✓ New database will be created on next run")
        else:
            print("\n✗ Cancel - Database preserved")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
else:
    print(f"\n✗ Database not found: {DB_PATH}")

print("\n" + "="*60 + "\n")
