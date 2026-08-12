export default function StatCard({
  label,
  value,
}: {
  label: string;
  value: number | string;
}) {
  return (
    <div className="rounded-lg border border-[#e3d8c4] bg-[#fbf7ef] p-5">
      <p className="text-sm text-[#6f6552]">{label}</p>
      <p className="mt-2 text-3xl font-semibold text-[#2b2318]">{value}</p>
    </div>
  );
}
