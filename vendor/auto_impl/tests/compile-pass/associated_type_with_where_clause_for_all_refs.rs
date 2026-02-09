use auto_impl::auto_impl;

#[auto_impl(Arc, Box, Rc, &, &mut)]
trait HasAssociatedTypeWithBounds {
    type AssociatedType<'a, T: From<usize> + 'a>;
}

#[auto_impl(Arc, Box, Rc, &, &mut)]
trait HasAssociatedTypeWithBoundsAndWhereClause {
    type AssociatedType<'a, T>
    where
        T: From<usize> + 'a;
}

#[auto_impl(Arc, Box, Rc, &, &mut)]
trait HasAssociatedTypeWithRedundantBoundsAndWhereClause {
    type AssociatedType<'a, T: From<usize> + 'a>
    where
        T: From<usize> + 'a;
}

fn main() {}
