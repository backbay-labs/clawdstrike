import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap text-[0.9375rem] font-medium tracking-normal transition-[box-shadow,background-color,color,transform] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 active:scale-[0.99]",
  {
    variants: {
      variant: {
        /** Primary black pill (DESIGN.md §4) */
        default:
          'rounded-full bg-primary text-primary-foreground shadow-none hover:bg-primary/88',
        destructive:
          'rounded-full bg-destructive text-destructive-foreground shadow-eleven-outline hover:bg-destructive/90',
        /** White pill, shadow-as-border */
        outline:
          'rounded-full border border-border/70 bg-background text-foreground shadow-eleven-card hover:bg-surface-muted/60 dark:border-border dark:bg-card/40 dark:shadow-eleven-outline',
        secondary:
          'rounded-full bg-secondary text-secondary-foreground shadow-eleven-outline hover:bg-secondary/85',
        /** Warm stone signature CTA */
        warm:
          '!h-auto min-h-[44px] rounded-[1.875rem] border-0 bg-accent px-5 py-3 pl-3.5 text-foreground shadow-eleven-warm hover:shadow-[0_8px_20px_rgb(78_50_23_/0.055)]',
        ghost:
          'rounded-full hover:bg-black/[0.04] hover:text-foreground dark:hover:bg-white/[0.06]',
        link: 'h-auto !min-h-0 rounded-none px-0 py-0 text-primary underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-10 px-3.5',
        sm: 'h-8 gap-1.5 rounded-full px-3 text-xs',
        lg: 'h-11 rounded-full px-6 text-base',
        icon: 'size-10 rounded-full p-0',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

export { Button, buttonVariants };
