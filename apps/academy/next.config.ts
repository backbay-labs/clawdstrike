import createMDX from '@next/mdx';
import type { NextConfig } from 'next';

const withMDX = createMDX();

const nextConfig: NextConfig = {
  pageExtensions: ['ts', 'tsx', 'md', 'mdx'],
};

export default withMDX(nextConfig);
