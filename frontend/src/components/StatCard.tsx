export default function StatCard({
  label,
  value,
}: {
  label: string;
  value: number | string;
}) {
  return (
    <div className="rounded-lg border border-[#b9d6cf] bg-[#fbf7ef] p-5">
      <p className="text-sm text-[#4f716c]">{label}</p>
      <p className="mt-2 text-3xl font-semibold text-[#123331]">{value}</p>
    </div>
  );
}
