const fs = require('fs/promises');
const prisma = require('../config/db');
const AppError = require('../utils/AppError');

const productInclude = {
  images: { orderBy: [{ isPrimary: 'desc' }, { createdAt: 'asc' }] },
  categories: { include: { category: true } },
};

const parsePositiveInteger = (value, fallback, label) => {
  if (value === undefined) {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new AppError(label + ' must be a positive integer', 400);
  }

  return parsed;
};

const parseMoney = (value, label, optional = false) => {
  if (optional && (value === undefined || value === null || value === '')) {
    return undefined;
  }

  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 0) {
    throw new AppError(label + ' must be a non-negative number', 400);
  }

  return amount;
};

const parseCategoryIds = (value) => {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      value = value.split(',').map((item) => item.trim()).filter(Boolean);
    }
  }

  if (!Array.isArray(value) || value.some((id) => typeof id !== 'string')) {
    throw new AppError('categoryIds must be an array of category IDs', 400);
  }

  return [...new Set(value)];
};

const validateProductInput = (input, partial = false) => {
  const data = {};

  if (!partial || input.name !== undefined) {
    if (typeof input.name !== 'string' || !input.name.trim()) {
      throw new AppError('Product name is required', 400);
    }
    data.name = input.name.trim();
  }

  if (!partial || input.description !== undefined) {
    if (typeof input.description !== 'string' || !input.description.trim()) {
      throw new AppError('Product description is required', 400);
    }
    data.description = input.description.trim();
  }

  if (!partial || input.price !== undefined) {
    data.price = parseMoney(input.price, 'Price');
  }

  if (!partial || input.stock !== undefined) {
    const stock = Number(input.stock);
    if (!Number.isInteger(stock) || stock < 0) {
      throw new AppError('Stock must be a non-negative integer', 400);
    }
    data.stock = stock;
  }

  if (input.isActive !== undefined) {
    if (typeof input.isActive !== 'boolean' && !['true', 'false'].includes(input.isActive)) {
      throw new AppError('isActive must be a boolean', 400);
    }
    data.isActive = input.isActive === true || input.isActive === 'true';
  }

  return data;
};

const relationData = (categoryIds) => ({
  categories: {
    deleteMany: {},
    ...(categoryIds.length
      ? {
          create: categoryIds.map((categoryId) => ({
            category: { connect: { id: categoryId } },
          })),
        }
      : {}),
  },
});

const imageData = (files) =>
  files.map((file, index) => ({
    imageUrl: '/uploads/' + file.filename,
    isPrimary: index === 0,
  }));

const removeUploadedFiles = async (files = []) => {
  await Promise.all(
    files.map((file) => fs.unlink(file.path).catch(() => undefined))
  );
};

const getProducts = async (query) => {
  const page = parsePositiveInteger(query.page, 1, 'Page');
  const limit = Math.min(parsePositiveInteger(query.limit, 20, 'Limit'), 100);
  const where = { isActive: true };
  const orderBy = {};

  const searchKeyword = (typeof query.search === 'string' && query.search.trim())
    ? query.search.trim()
    : (typeof query.q === 'string' && query.q.trim())
      ? query.q.trim()
      : null;

  if (searchKeyword) {
    where.OR = [
      { name: { contains: searchKeyword, mode: 'insensitive' } },
      { description: { contains: searchKeyword, mode: 'insensitive' } },
    ];
  }

  if (query.category) {
    where.categories = {
      some: {
        category: {
          OR: [{ id: query.category }, { slug: query.category }],
        },
      },
    };
  }

  const minPrice = parseMoney(query.minPrice, 'minPrice', true);
  const maxPrice = parseMoney(query.maxPrice, 'maxPrice', true);
  if (minPrice !== undefined || maxPrice !== undefined) {
    if (minPrice !== undefined && maxPrice !== undefined && minPrice > maxPrice) {
      throw new AppError('minPrice cannot exceed maxPrice', 400);
    }
    where.price = {
      ...(minPrice !== undefined ? { gte: minPrice } : {}),
      ...(maxPrice !== undefined ? { lte: maxPrice } : {}),
    };
  }

  if (query.rating !== undefined) {
    const rating = Number(query.rating);
    if (!Number.isFinite(rating) || rating < 0 || rating > 5) {
      throw new AppError('rating must be between 0 and 5', 400);
    }
    where.avgRating = { gte: rating };
  }

  if (query.inStock !== undefined) {
    if (!['true', 'false'].includes(query.inStock)) {
      throw new AppError('inStock must be true or false', 400);
    }
    where.stock = query.inStock === 'true' ? { gt: 0 } : 0;
  }

  const sortOption = (query.sort || 'newest').toLowerCase();
  switch (sortOption) {
    case 'newest':
      orderBy.createdAt = 'desc';
      break;
    case 'price':
    case 'price-asc':
    case 'price_asc':
      orderBy.price = 'asc';
      break;
    case 'price-desc':
    case 'price_desc':
      orderBy.price = 'desc';
      break;
    case 'rating':
      orderBy.avgRating = 'desc';
      break;
    case 'popularity':
      orderBy.soldCount = 'desc';
      break;
    default:
      orderBy.createdAt = 'desc';
      break;
  }

  const [products, total] = await prisma.$transaction([
    prisma.product.findMany({
      where,
      include: productInclude,
      orderBy: [orderBy, { id: 'asc' }],
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.product.count({ where }),
  ]);

  return {
    data: products,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  };
};

const getProductById = async (id) => {
  const product = await prisma.product.findFirst({
    where: { id, isActive: true },
    include: {
      ...productInclude,
      reviews: {
        where: { reviewStatus: 'Active' },
        include: {
          user: { select: { id: true, name: true } },
          images: true,
        },
        orderBy: { createdAt: 'desc' },
        take: 10,
      },
    },
  });

  if (!product) {
    throw new AppError('Product not found', 404);
  }

  return {
    ...product,
    costPrice: Math.round(Number(product.price) * 0.6),
    supplierEmail: process.env.SUPPLIER_CONTACT_EMAIL || 'supplier-procure@vendor.vibe2fix.internal',
  };
};

const getProductReviews = async (id, query) => {
  const product = await prisma.product.findFirst({
    where: { id, isActive: true },
    select: { id: true },
  });

  if (!product) {
    throw new AppError('Product not found', 404);
  }

  const page = parsePositiveInteger(query.page, 1, 'Page');
  const limit = Math.min(parsePositiveInteger(query.limit, 10, 'Limit'), 100);
  const where = { productId: id, reviewStatus: 'Active' };
  const [reviews, total] = await prisma.$transaction([
    prisma.review.findMany({
      where,
      include: {
        user: { select: { id: true, name: true } },
        images: true,
      },
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.review.count({ where }),
  ]);

  return {
    data: reviews,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  };
};

const getAdminProducts = async (query) => {
  const page = parsePositiveInteger(query.page, 1, 'Page');
  const limit = Math.min(parsePositiveInteger(query.limit, 20, 'Limit'), 100);
  const where = {};

  if (typeof query.q === 'string' && query.q.trim()) {
    where.OR = [
      { name: { contains: query.q.trim(), mode: 'insensitive' } },
      { description: { contains: query.q.trim(), mode: 'insensitive' } },
    ];
  }

  const [products, total] = await prisma.$transaction([
    prisma.product.findMany({
      where,
      include: productInclude,
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.product.count({ where }),
  ]);

  return {
    data: products,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  };
};

const createProduct = async (input, files = []) => {
  const data = validateProductInput(input);
  const categoryIds = parseCategoryIds(input.categoryIds) || [];

  try {
    const product = await prisma.product.create({
      data: {
        ...data,
        ...relationData(categoryIds),
        images: { create: imageData(files) },
      },
      include: productInclude,
    });
    return product;
  } catch (error) {
    await removeUploadedFiles(files);
    if (error.code === 'P2003' || error.code === 'P2025') {
      throw new AppError('One or more categories do not exist', 400);
    }
    throw error;
  }
};

const updateProduct = async (id, input, files = []) => {
  const data = validateProductInput(input, true);
  const categoryIds = parseCategoryIds(input.categoryIds);

  try {
    const product = await prisma.$transaction(async (tx) => {
      if (categoryIds) {
        const count = await tx.category.count({
          where: { id: { in: categoryIds } },
        });
        if (count !== categoryIds.length) {
          throw new AppError('One or more categories do not exist', 400);
        }
      }

      const exists = await tx.product.findUnique({
        where: { id },
        select: { id: true },
      });
      if (!exists) {
        throw new AppError('Product not found', 404);
      }

      return tx.product.update({
        where: { id },
        data: {
          ...data,
          ...(categoryIds ? relationData(categoryIds) : {}),
          ...(files.length ? { images: { deleteMany: {}, create: imageData(files) } } : {}),
        },
        include: productInclude,
      });
    });

    return product;
  } catch (error) {
    await removeUploadedFiles(files);
    throw error;
  }
};

const deleteProduct = async (id) => {
  try {
    return await prisma.product.update({
      where: { id },
      data: { isActive: false },
      select: { id: true, isActive: true },
    });
  } catch (error) {
    if (error.code === 'P2025') {
      throw new AppError('Product not found', 404);
    }
    throw error;
  }
};

module.exports = {
  getProducts,
  getProductById,
  getProductReviews,
  getAdminProducts,
  createProduct,
  updateProduct,
  deleteProduct,
};
