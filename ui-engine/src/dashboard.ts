import definitions from './dashboard.json';
import type { ChartConfig } from './engine/chartTypes';

export type DashboardBlock = {
  kind: 'heading' | 'text' | 'query';
  text?: string;
  sql?: string;
  chart?: ChartConfig;
};
export const dashboard = definitions as DashboardBlock[];
