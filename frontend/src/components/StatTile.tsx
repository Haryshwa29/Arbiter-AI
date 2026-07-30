export function StatTile({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: "red" | "neutral";
}) {
  return (
    <div className="rounded-lg border border-neutral-200 bg-white px-4 py-3 dark:border-neutral-800 dark:bg-neutral-900/40">
      <p className="text-xs text-neutral-500">{label}</p>
      <p
        className={`mt-1 text-2xl font-medium tabular-nums ${
          accent === "red" ? "text-[#C2402F] dark:text-[#E2574B]" : "text-neutral-900 dark:text-neutral-100"
        }`}
      >
        {value}
      </p>
    </div>
  );
}
