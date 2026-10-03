import sqlite3
from pathlib import Path

# ============================================================
# SURAKSHA DATABASE ANALYZER
# ============================================================

DB_PATH = Path("database/scanner.db")


def print_line(char="=", length=80):
    print(char * length)


def analyze_database():
    if not DB_PATH.exists():
        print(f"❌ Database not found: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print_line()
    print("        SURAKSHA DATABASE STRUCTURE & CONSTRAINT ANALYZER")
    print_line()
    print(f"Database: {DB_PATH.resolve()}")
    print()

    # --------------------------------------------------------
    # DATABASE TABLES
    # --------------------------------------------------------
    cursor.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name NOT LIKE 'sqlite_%'
        ORDER BY name
    """)

    tables = [row[0] for row in cursor.fetchall()]

    print(f"Tables Found: {len(tables)}")
    print()

    if not tables:
        print("❌ No tables found.")
        conn.close()
        return

    # --------------------------------------------------------
    # ANALYSE EACH TABLE
    # --------------------------------------------------------
    for table in tables:

        print_line()
        print(f"TABLE: {table}")
        print_line("-")

        # ====================================================
        # COLUMNS
        # ====================================================
        cursor.execute(f'PRAGMA table_info("{table}")')
        columns = cursor.fetchall()

        print("\n[COLUMNS]")
        print("-" * 80)

        print(
            f"{'CID':<5}"
            f"{'NAME':<22}"
            f"{'TYPE':<18}"
            f"{'NOT NULL':<12}"
            f"{'DEFAULT':<15}"
            f"{'PK':<5}"
        )

        print("-" * 80)

        for col in columns:
            cid, name, data_type, not_null, default, pk = col

            print(
                f"{cid:<5}"
                f"{name:<22}"
                f"{data_type:<18}"
                f"{'YES' if not_null else 'NO':<12}"
                f"{str(default) if default is not None else '-':<15}"
                f"{pk:<5}"
            )

        # ====================================================
        # PRIMARY KEY
        # ====================================================
        primary_keys = [
            col[1]
            for col in columns
            if col[5] > 0
        ]

        print("\n[PRIMARY KEY]")
        if primary_keys:
            print("  ✔", ", ".join(primary_keys))
        else:
            print("  ❌ No primary key")

        # ====================================================
        # FOREIGN KEYS
        # ====================================================
        cursor.execute(f'PRAGMA foreign_key_list("{table}")')
        foreign_keys = cursor.fetchall()

        print("\n[FOREIGN KEYS]")

        if foreign_keys:
            for fk in foreign_keys:
                (
                    fk_id,
                    seq,
                    ref_table,
                    from_column,
                    to_column,
                    on_update,
                    on_delete,
                    match
                ) = fk

                print(
                    f"  ✔ {from_column} → "
                    f"{ref_table}.{to_column}"
                )
                print(f"    ON UPDATE : {on_update}")
                print(f"    ON DELETE : {on_delete}")
        else:
            print("  - No foreign keys")

        # ====================================================
        # INDEXES
        # ====================================================
        cursor.execute(f'PRAGMA index_list("{table}")')
        indexes = cursor.fetchall()

        print("\n[INDEXES]")

        if indexes:
            for index in indexes:
                seq, index_name, unique, origin, partial = index

                print(
                    f"  ✔ {index_name}"
                    f" | UNIQUE: {'YES' if unique else 'NO'}"
                    f" | ORIGIN: {origin}"
                )

                cursor.execute(f'PRAGMA index_info("{index_name}")')
                index_columns = cursor.fetchall()

                for idx_col in index_columns:
                    print(f"      └── {idx_col[2]}")
        else:
            print("  - No indexes")

        # ====================================================
        # UNIQUE CONSTRAINTS
        # ====================================================
        print("\n[UNIQUE CONSTRAINTS]")

        unique_found = False

        for index in indexes:
            seq, index_name, unique, origin, partial = index

            if unique:
                unique_found = True

                cursor.execute(
                    f'PRAGMA index_info("{index_name}")'
                )

                unique_columns = [
                    row[2]
                    for row in cursor.fetchall()
                ]

                print(
                    f"  ✔ {index_name}: "
                    f"{', '.join(unique_columns)}"
                )

        if not unique_found:
            print("  - No UNIQUE constraints")

        # ====================================================
        # NOT NULL CONSTRAINTS
        # ====================================================
        print("\n[NOT NULL CONSTRAINTS]")

        not_null_columns = [
            col[1]
            for col in columns
            if col[3]
        ]

        if not_null_columns:
            for column in not_null_columns:
                print(f"  ✔ {column}")
        else:
            print("  - No NOT NULL constraints")

        # ====================================================
        # DEFAULT VALUES
        # ====================================================
        print("\n[DEFAULT VALUES]")

        defaults_found = False

        for col in columns:
            if col[4] is not None:
                defaults_found = True
                print(f"  ✔ {col[1]} = {col[4]}")

        if not defaults_found:
            print("  - No default values")

        # ====================================================
        # TABLE ROW COUNT
        # ====================================================
        cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
        row_count = cursor.fetchone()[0]

        print("\n[ROW COUNT]")
        print(f"  {row_count}")

        # ====================================================
        # TABLE SQL / DDL
        # ====================================================
        cursor.execute("""
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
            AND name = ?
        """, (table,))

        table_sql = cursor.fetchone()

        print("\n[TABLE DDL]")

        if table_sql and table_sql[0]:
            print(table_sql[0])
        else:
            print("  - DDL not available")

        print()

    # --------------------------------------------------------
    # DATABASE FOREIGN KEY CHECK
    # --------------------------------------------------------
    print_line()
    print("DATABASE INTEGRITY CHECK")
    print_line()

    cursor.execute("PRAGMA foreign_keys")
    fk_status = cursor.fetchone()[0]

    print(
        f"Foreign Key Enforcement: "
        f"{'ENABLED' if fk_status else 'DISABLED'}"
    )

    # --------------------------------------------------------
    # FOREIGN KEY VIOLATION CHECK
    # --------------------------------------------------------
    cursor.execute("PRAGMA foreign_key_check")
    violations = cursor.fetchall()

    print("\nForeign Key Violations:")

    if violations:
        for violation in violations:
            print("  ❌", violation)
    else:
        print("  ✔ No foreign key violations")

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------
    print()
    print_line()
    print("DATABASE SUMMARY")
    print_line()

    total_rows = 0

    for table in tables:
        cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
        count = cursor.fetchone()[0]
        total_rows += count

        print(f"{table:<25} {count:>8} rows")

    print("-" * 40)
    print(f"{'TOTAL':<25} {total_rows:>8} rows")

    print_line()

    conn.close()


if __name__ == "__main__":
    analyze_database()