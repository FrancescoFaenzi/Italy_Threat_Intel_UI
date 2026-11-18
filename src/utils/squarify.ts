import type { TreemapNode, TreemapSizeMode } from '../types/intel';

export interface SquarifiedRect {
  node: TreemapNode;
  x: number;
  y: number;
  width: number;
  height: number;
}

interface WeightedItem {
  node: TreemapNode;
  area: number;
}

function worstAspectRatio(row: WeightedItem[], sideLength: number): number {
  if (row.length === 0 || sideLength <= 0) return Infinity;
  let sum = 0;
  let minArea = Infinity;
  let maxArea = 0;
  for (const item of row) {
    sum += item.area;
    if (item.area < minArea) minArea = item.area;
    if (item.area > maxArea) maxArea = item.area;
  }
  if (sum <= 0 || minArea <= 0) return Infinity;
  const s2 = sideLength * sideLength;
  return Math.max((s2 * maxArea) / (sum * sum), (sum * sum) / (s2 * minArea));
}

export function computeSquarifiedTreemap(
  nodes: TreemapNode[],
  containerWidth: number,
  containerHeight: number,
  sizeBy: TreemapSizeMode = 'count',
): SquarifiedRect[] {
  if (nodes.length === 0 || containerWidth <= 0 || containerHeight <= 0) {
    return [];
  }

  const getWeight = (node: TreemapNode) => {
    if (sizeBy === 'risk') {
      return Math.max(1, node.count * Math.pow(Math.max(6, node.avgRiskScore - 50), 2));
    }
    return node.count;
  };

  const positiveNodes = nodes.filter((n) => getWeight(n) > 0);
  if (positiveNodes.length === 0) return [];

  const totalWeight = positiveNodes.reduce((acc, n) => acc + getWeight(n), 0);
  const totalArea = containerWidth * containerHeight;

  const sorted: WeightedItem[] = [...positiveNodes]
    .sort((a, b) => getWeight(b) - getWeight(a) || b.count - a.count)
    .map((node) => ({
      node,
      area: (getWeight(node) / totalWeight) * totalArea,
    }));

  const rects: SquarifiedRect[] = [];

  let x = 0;
  let y = 0;
  let w = containerWidth;
  let h = containerHeight;

  const layoutRow = (row: WeightedItem[]) => {
    const rowSum = row.reduce((acc, r) => acc + r.area, 0);
    if (rowSum <= 0) return;

    if (w >= h) {
      const colWidth = rowSum / h;
      let curY = y;
      for (const item of row) {
        const itemHeight = item.area / colWidth;
        rects.push({
          node: item.node,
          x,
          y: curY,
          width: colWidth,
          height: itemHeight,
        });
        curY += itemHeight;
      }
      x += colWidth;
      w = Math.max(0, w - colWidth);
    } else {
      const rowHeight = rowSum / w;
      let curX = x;
      for (const item of row) {
        const itemWidth = item.area / rowHeight;
        rects.push({
          node: item.node,
          x: curX,
          y,
          width: itemWidth,
          height: rowHeight,
        });
        curX += itemWidth;
      }
      y += rowHeight;
      h = Math.max(0, h - rowHeight);
    }
  };

  const remaining = [...sorted];
  let currentRow: WeightedItem[] = [];

  while (remaining.length > 0) {
    const shortSide = Math.min(w, h);
    const next = remaining[0];

    if (currentRow.length === 0) {
      currentRow.push(next);
      remaining.shift();
      continue;
    }

    const withNext = [...currentRow, next];
    if (worstAspectRatio(withNext, shortSide) <= worstAspectRatio(currentRow, shortSide)) {
      currentRow.push(next);
      remaining.shift();
    } else {
      layoutRow(currentRow);
      currentRow = [];
    }
  }

  if (currentRow.length > 0) {
    layoutRow(currentRow);
  }

  return rects;
}
