/**
 * @description Creates a pagination result.
 * @param items - The items to paginate.
 * @param total - The total number of items.
 * @param page - The current page.
 * @param limit - The number of items per page.
 * @returns The pagination result.
 */
export const createPaginationResult = <T>({
  items,
  total,
  page,
  limit,
}: {
  total: number;
  page: number;
  limit: number;
  items: T[];
}) => {
  // Calculate the total pages.
  const totalPages = Math.ceil(total / limit);
  const hasNextPage = page < totalPages;
  const hasPreviousPage = page > 1;
  const nextPage = hasNextPage ? page + 1 : null;
  const previousPage = hasPreviousPage ? page - 1 : null;

  return {
    items,
    pagination: {
      totalPages,
      pageSize: limit,
      currentPage: page,
      nextPage,
      previousPage,
      totalItems: total,
    },
  };
};
