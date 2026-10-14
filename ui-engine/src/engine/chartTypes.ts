export type ChartConfig = {
  title: string;
  type: 'bar' | 'line' | 'doughnut';
  sql: string;
  x: string;
  y: string;
  width: number;
  height: number;
  wrap: 'left' | 'right' | 'none';
};
