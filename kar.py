# generate_ranges.py

START_PUZZLE = 71
END_PUZZLE = 190

OUTPUT_FILE = "range.txt"

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for puzzle in range(START_PUZZLE, END_PUZZLE + 1):
        start = 1 << (puzzle - 1)
        end = (1 << puzzle) - 1

        f.write(f"# Puzzle {puzzle}\n")
        f.write(f"{start} {end}\n")

print(f"رنج پازل‌های {START_PUZZLE} تا {END_PUZZLE} ساخته شد.")
print(f"فایل: {OUTPUT_FILE}")
