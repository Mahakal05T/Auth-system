import logging
import re
import secrets
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor, is_mysql

products_bp = Blueprint('products', __name__)

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return wrapper

def slugify(text):
    text = re.sub(r'[^\w\s-]', '', text).strip().lower()
    return re.sub(r'[-\s]+', '-', text)

def check_category_cycle(cursor, category_id, target_parent_id):
    """Check if setting target_parent_id as parent of category_id would cause a circular cycle."""
    if not target_parent_id:
        return False
    if category_id == target_parent_id:
        return True
    curr = target_parent_id
    visited = set()
    while curr:
        if curr == category_id:
            return True
        if curr in visited:
            break
        visited.add(curr)
        cursor.execute("SELECT parent_id FROM categories WHERE id=%s", (curr,))
        row = cursor.fetchone()
        curr = row["parent_id"] if row and row.get("parent_id") else None
    return False

# ==========================================================
# CATEGORIES API (STOREFRONT & ADMIN)
# ==========================================================

@products_bp.route("/categories", methods=["GET"])
def get_categories():
    """Storefront: Fetch active categories ordered by display_order, with product count and hierarchy."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT c.id, c.parent_id, c.name, c.slug, c.description, c.image_url, 
                   c.is_active, c.display_order,
                   p_cat.name as parent_name,
                   COUNT(p.id) as product_count
            FROM categories c
            LEFT JOIN categories p_cat ON c.parent_id = p_cat.id
            LEFT JOIN products p ON c.id = p.category_id AND p.is_active = TRUE
            WHERE c.is_active = TRUE
            GROUP BY c.id, c.parent_id, c.name, c.slug, c.description, c.image_url, 
                     c.is_active, c.display_order, p_cat.name
            ORDER BY c.display_order ASC, c.name ASC
        """)
        raw_cats = cursor.fetchall()
        categories = []
        for c in raw_cats:
            cat = dict(c)
            cat["product_count"] = int(cat.get("product_count") or 0)
            categories.append(cat)

        # Build nested tree structure for convenience
        category_map = {c["id"]: {**c, "children": []} for c in categories}
        root_categories = []
        for c in categories:
            cid = c["id"]
            pid = c.get("parent_id")
            if pid and pid in category_map:
                category_map[pid]["children"].append(category_map[cid])
            else:
                root_categories.append(category_map[cid])

        return jsonify({
            "success": True, 
            "categories": categories,
            "tree": root_categories
        }), 200
    except Exception as e:
        logging.error(f"Error fetching categories: {e}")
        return jsonify({"success": False, "error": "Failed to fetch categories"}), 500
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/categories/<identifier>", methods=["GET"])
def get_category(identifier):
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        if identifier.isdigit():
            cursor.execute("""
                SELECT c.*, p_cat.name as parent_name, COUNT(p.id) as product_count
                FROM categories c
                LEFT JOIN categories p_cat ON c.parent_id = p_cat.id
                LEFT JOIN products p ON c.id = p.category_id AND p.is_active = TRUE
                WHERE c.id=%s
                GROUP BY c.id, p_cat.name
                LIMIT 1
            """, (int(identifier),))
        else:
            cursor.execute("""
                SELECT c.*, p_cat.name as parent_name, COUNT(p.id) as product_count
                FROM categories c
                LEFT JOIN categories p_cat ON c.parent_id = p_cat.id
                LEFT JOIN products p ON c.id = p.category_id AND p.is_active = TRUE
                WHERE c.slug=%s
                GROUP BY c.id, p_cat.name
                LIMIT 1
            """, (identifier.lower(),))
            
        category = cursor.fetchone()
        if not category:
            return jsonify({"success": False, "error": "Category not found"}), 404
            
        cat_dict = dict(category)
        cat_dict["product_count"] = int(cat_dict.get("product_count") or 0)

        # Also get subcategories
        cursor.execute("""
            SELECT id, name, slug, image_url, display_order
            FROM categories
            WHERE parent_id=%s AND is_active=TRUE
            ORDER BY display_order ASC, name ASC
        """, (cat_dict["id"],))
        cat_dict["children"] = [dict(r) for r in cursor.fetchall()]

        return jsonify({"success": True, "category": cat_dict}), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/categories", methods=["GET"])
@admin_required
def admin_get_categories():
    """Admin: Fetch all categories with KPIs, search, filtering, and hierarchy counts."""
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "all").lower()
    level = request.args.get("level", "all").lower()

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT c.id, c.parent_id, c.name, c.slug, c.description, c.image_url, 
                   c.is_active, c.display_order, c.created_at,
                   p_cat.name as parent_name,
                   (SELECT COUNT(*) FROM products p WHERE p.category_id = c.id) as product_count,
                   (SELECT COUNT(*) FROM categories sub WHERE sub.parent_id = c.id) as subcategory_count
            FROM categories c
            LEFT JOIN categories p_cat ON c.parent_id = p_cat.id
            ORDER BY c.display_order ASC, c.name ASC
        """)
        all_cats = [dict(r) for r in cursor.fetchall()]

        # Filter in memory or query
        filtered = []
        for c in all_cats:
            # search
            if search:
                term = search.lower()
                matches = term in c["name"].lower() or term in (c.get("slug") or "").lower() or term in (c.get("description") or "").lower()
                if not matches:
                    continue
            # status
            if status == "active" and not c["is_active"]:
                continue
            if status == "inactive" and c["is_active"]:
                continue
            # level
            if level == "root" and c["parent_id"] is not None:
                continue
            if level == "sub" and c["parent_id"] is None:
                continue

            filtered.append(c)

        # Statistics
        total_cats = len(all_cats)
        active_cats = sum(1 for c in all_cats if c["is_active"])
        root_cats = sum(1 for c in all_cats if c["parent_id"] is None)
        sub_cats = total_cats - root_cats
        total_products_linked = sum(c["product_count"] for c in all_cats)

        cursor.execute("SELECT COUNT(*) as count FROM products WHERE category_id IS NULL")
        uncat_res = cursor.fetchone()
        uncategorized_products = uncat_res["count"] if uncat_res else 0

        stats = {
            "total_categories": total_cats,
            "active_categories": active_cats,
            "root_categories": root_cats,
            "subcategories": sub_cats,
            "total_products_linked": total_products_linked,
            "uncategorized_products": uncategorized_products
        }

        return jsonify({
            "success": True,
            "categories": filtered,
            "stats": stats
        }), 200
    except Exception as e:
        logging.error(f"Error fetching admin categories: {e}")
        return jsonify({"success": False, "error": "Failed to fetch admin categories"}), 500
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/categories", methods=["POST"])
@admin_required
def create_category():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    description = data.get("description", "").strip()
    image_url = data.get("image_url", "").strip()
    parent_id = data.get("parent_id")
    display_order = data.get("display_order", 0)
    is_active = data.get("is_active", True)

    if not name:
        return jsonify({"success": False, "error": "Category name is required"}), 400

    slug = (data.get("slug") or "").strip() or slugify(name)
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id FROM categories WHERE slug=%s OR name=%s", (slug, name))
        if cursor.fetchone():
            return jsonify({"success": False, "error": "Category with this name or slug already exists"}), 409

        if parent_id:
            cursor.execute("SELECT id FROM categories WHERE id=%s", (parent_id,))
            if not cursor.fetchone():
                return jsonify({"success": False, "error": "Parent category not found"}), 404

        cursor.execute("""
            INSERT INTO categories (parent_id, name, slug, description, image_url, is_active, display_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (parent_id if parent_id else None, name, slug, description, image_url, bool(is_active), int(display_order or 0)))
        conn.commit()

        new_id = cursor.lastrowid
        cursor.execute("""
            SELECT c.*, p_cat.name as parent_name, 0 as product_count, 0 as subcategory_count
            FROM categories c
            LEFT JOIN categories p_cat ON c.parent_id = p_cat.id
            WHERE c.id=%s
        """, (new_id,))
        created = cursor.fetchone()

        return jsonify({
            "success": True, 
            "message": f"Category '{name}' created successfully", 
            "category": dict(created) if created else None
        }), 201
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/categories/<int:category_id>", methods=["PUT"])
@admin_required
def update_category(category_id):
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    slug = data.get("slug")
    description = data.get("description")
    image_url = data.get("image_url")
    parent_id = data.get("parent_id")
    display_order = data.get("display_order")
    is_active = data.get("is_active")

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, name, slug, parent_id FROM categories WHERE id=%s", (category_id,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({"success": False, "error": "Category not found"}), 404

        updates = []
        params = []

        if name is not None:
            name_str = name.strip()
            if not name_str:
                return jsonify({"success": False, "error": "Category name cannot be empty"}), 400
            # Check duplicate name
            cursor.execute("SELECT id FROM categories WHERE name=%s AND id!=%s", (name_str, category_id))
            if cursor.fetchone():
                return jsonify({"success": False, "error": "Category name already in use"}), 409
            updates.append("name = %s")
            params.append(name_str)

        if slug is not None:
            slug_str = slug.strip() or slugify(name or existing["name"])
            cursor.execute("SELECT id FROM categories WHERE slug=%s AND id!=%s", (slug_str, category_id))
            if cursor.fetchone():
                return jsonify({"success": False, "error": "Slug already in use"}), 409
            updates.append("slug = %s")
            params.append(slug_str)

        if "parent_id" in data:
            if parent_id:
                # Cycle check
                if check_category_cycle(cursor, category_id, int(parent_id)):
                    return jsonify({"success": False, "error": "Circular category hierarchy detected: A category cannot be parented by itself or its descendants"}), 400
                cursor.execute("SELECT id FROM categories WHERE id=%s", (parent_id,))
                if not cursor.fetchone():
                    return jsonify({"success": False, "error": "Selected parent category does not exist"}), 404
                updates.append("parent_id = %s")
                params.append(int(parent_id))
            else:
                updates.append("parent_id = NULL")

        if description is not None:
            updates.append("description = %s")
            params.append(description.strip())

        if image_url is not None:
            updates.append("image_url = %s")
            params.append(image_url.strip())

        if display_order is not None:
            updates.append("display_order = %s")
            params.append(int(display_order))

        if is_active is not None:
            updates.append("is_active = %s")
            params.append(bool(is_active))

        if updates:
            params.append(category_id)
            cursor.execute(f"UPDATE categories SET {', '.join(updates)} WHERE id=%s", tuple(params))
            conn.commit()

        cursor.execute("""
            SELECT c.*, p_cat.name as parent_name,
                   (SELECT COUNT(*) FROM products p WHERE p.category_id = c.id) as product_count,
                   (SELECT COUNT(*) FROM categories sub WHERE sub.parent_id = c.id) as subcategory_count
            FROM categories c
            LEFT JOIN categories p_cat ON c.parent_id = p_cat.id
            WHERE c.id=%s
        """, (category_id,))
        updated = cursor.fetchone()

        return jsonify({
            "success": True, 
            "message": "Category updated successfully",
            "category": dict(updated) if updated else None
        }), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/categories/<int:category_id>/toggle-status", methods=["PATCH"])
@admin_required
def toggle_category_status(category_id):
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, name, is_active FROM categories WHERE id=%s", (category_id,))
        cat = cursor.fetchone()
        if not cat:
            return jsonify({"success": False, "error": "Category not found"}), 404

        new_status = not bool(cat["is_active"])
        cursor.execute("UPDATE categories SET is_active=%s WHERE id=%s", (new_status, category_id))
        conn.commit()

        status_text = "activated" if new_status else "deactivated"
        return jsonify({
            "success": True,
            "is_active": new_status,
            "message": f"Category '{cat['name']}' has been {status_text}."
        }), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/categories/reorder", methods=["PATCH"])
@admin_required
def reorder_categories():
    """Batch update display_order for categories."""
    data = request.get_json(silent=True) or {}
    orders = data.get("orders", []) # list of {"id": int, "display_order": int}

    if not orders:
        return jsonify({"success": False, "error": "Orders array is required"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        for item in orders:
            cat_id = item.get("id")
            disp_order = item.get("display_order", 0)
            if cat_id is not None:
                cursor.execute("UPDATE categories SET display_order=%s WHERE id=%s", (int(disp_order), int(cat_id)))
        conn.commit()
        return jsonify({"success": True, "message": "Categories reordered successfully"}), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/categories/<int:category_id>", methods=["DELETE"])
@admin_required
def delete_category(category_id):
    """Delete category. If products or subcategories exist, safely reassign or soft delete."""
    reassign_to = request.args.get("reassign_to", type=int) # optional new category_id
    hard_delete = request.args.get("hard_delete", "false").lower() == "true"

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, name, parent_id FROM categories WHERE id=%s", (category_id,))
        cat = cursor.fetchone()
        if not cat:
            return jsonify({"success": False, "error": "Category not found"}), 404

        # Count linked products
        cursor.execute("SELECT COUNT(*) as count FROM products WHERE category_id=%s", (category_id,))
        prod_count = cursor.fetchone()["count"]

        # Count children
        cursor.execute("SELECT COUNT(*) as count FROM categories WHERE parent_id=%s", (category_id,))
        sub_count = cursor.fetchone()["count"]

        if hard_delete:
            # Reassign children subcategories to this category's parent
            cursor.execute("UPDATE categories SET parent_id=%s WHERE parent_id=%s", (cat["parent_id"], category_id))
            # Reassign products
            if reassign_to:
                cursor.execute("UPDATE products SET category_id=%s WHERE category_id=%s", (reassign_to, category_id))
            else:
                cursor.execute("UPDATE products SET category_id=NULL WHERE category_id=%s", (category_id,))
            
            cursor.execute("DELETE FROM categories WHERE id=%s", (category_id,))
            conn.commit()
            return jsonify({
                "success": True, 
                "action": "deleted", 
                "message": f"Category '{cat['name']}' was permanently removed."
            }), 200
        else:
            # Soft deactivate
            cursor.execute("UPDATE categories SET is_active=FALSE WHERE id=%s", (category_id,))
            conn.commit()
            return jsonify({
                "success": True, 
                "action": "deactivated", 
                "message": f"Category '{cat['name']}' has been deactivated."
            }), 200
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# PRODUCTS STOREFRONT & SEARCH API
# ==========================================================

@products_bp.route("/products", methods=["GET"])
def get_products():
    category_param = request.args.get("category")
    q = request.args.get("q", "").strip()
    brand = request.args.get("brand", "").strip()
    badge = request.args.get("badge", "").strip()
    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)
    in_stock = request.args.get("in_stock")
    sort = request.args.get("sort", "popular").lower()
    page = max(1, request.args.get("page", 1, type=int))
    limit = min(50, max(1, request.args.get("limit", 12, type=int)))
    offset = (page - 1) * limit

    conditions = ["p.is_active = TRUE"]
    params = []

    if category_param:
        if category_param.isdigit():
            conditions.append("p.category_id = %s")
            params.append(int(category_param))
        else:
            conditions.append("(LOWER(c.slug) = %s OR LOWER(c.name) LIKE %s)")
            params.extend([category_param.lower(), f"%{category_param.lower()}%"])

    if q:
        conditions.append("(LOWER(p.name) LIKE %s OR LOWER(p.description) LIKE %s OR LOWER(p.brand) LIKE %s)")
        q_wild = f"%{q.lower()}%"
        params.extend([q_wild, q_wild, q_wild])

    if brand:
        conditions.append("LOWER(p.brand) = %s")
        params.append(brand.lower())

    if badge == "deal":
        conditions.append("p.discount_price IS NOT NULL AND p.discount_price > 0 AND p.discount_price < p.price")

    if min_price is not None:
        conditions.append("COALESCE(p.discount_price, p.price) >= %s")
        params.append(min_price)

    if max_price is not None:
        conditions.append("COALESCE(p.discount_price, p.price) <= %s")
        params.append(max_price)

    if in_stock in ("true", "1"):
        conditions.append("p.stock > 0")

    order_clause = "p.id DESC"
    if sort in ("price_asc", "price-low"):
        order_clause = "COALESCE(p.discount_price, p.price) ASC"
    elif sort in ("price_desc", "price-high"):
        order_clause = "COALESCE(p.discount_price, p.price) DESC"
    elif sort == "newest":
        order_clause = "p.created_at DESC"
    elif sort in ("name_asc", "name"):
        order_clause = "p.name ASC"

    where_clause = " AND ".join(conditions)

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Count total matches
        count_sql = f"""
            SELECT COUNT(*) as total
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE {where_clause}
        """
        cursor.execute(count_sql, tuple(params))
        total_row = cursor.fetchone()
        total = total_row["total"] if isinstance(total_row, dict) else (total_row[0] if total_row else 0)

        # Select page rows
        query_sql = f"""
            SELECT p.id, p.name, p.slug, p.description, p.price, p.discount_price,
                   p.stock, p.sku, p.brand, p.is_active, p.created_at,
                   c.name as category_name, c.slug as category_slug,
                   (
                       SELECT image_url FROM product_images pi 
                       WHERE pi.product_id = p.id 
                       ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                   ) as primary_image
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE {where_clause}
            ORDER BY {order_clause}
            LIMIT %s OFFSET %s
        """
        fetch_params = list(params) + [limit, offset]
        cursor.execute(query_sql, tuple(fetch_params))
        products = [dict(r) for r in cursor.fetchall()]

        # Format numeric floats and default images
        for p in products:
            p["price"] = float(p["price"]) if p.get("price") is not None else 0.0
            p["discount_price"] = float(p["discount_price"]) if p.get("discount_price") is not None else None
            p["image"] = p.get("primary_image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80"
            p["inStock"] = p.get("stock", 0) > 0

        total_pages = (total + limit - 1) // limit if total > 0 else 1

        return jsonify({
            "success": True,
            "data": {
                "products": products,
                "total": total,
                "page": page,
                "limit": limit,
                "total_pages": total_pages
            }
        }), 200
    except Exception as e:
        logging.error(f"Error fetching products: {e}")
        return jsonify({"success": False, "error": "Failed to query products"}), 500
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/products/<int:product_id>", methods=["GET"])
def get_product_detail(product_id):
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT p.*, c.name as category_name, c.slug as category_slug
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.id = %s AND p.is_active = TRUE
            LIMIT 1
        """, (product_id,))
        product = cursor.fetchone()
        if not product:
            return jsonify({"success": False, "error": "Product not found"}), 404

        prod_dict = dict(product)
        prod_dict["price"] = float(prod_dict["price"]) if prod_dict.get("price") is not None else 0.0
        prod_dict["discount_price"] = float(prod_dict["discount_price"]) if prod_dict.get("discount_price") is not None else None

        # Fetch all images
        cursor.execute("""
            SELECT id, image_url, is_primary FROM product_images
            WHERE product_id = %s ORDER BY is_primary DESC, id ASC
        """, (product_id,))
        images = [dict(img) for img in cursor.fetchall()]
        prod_dict["images"] = images
        prod_dict["image"] = images[0]["image_url"] if images else "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80"
        prod_dict["inStock"] = prod_dict.get("stock", 0) > 0

        # Fetch reviews summary
        cursor.execute("""
            SELECT COUNT(*) as reviews_count, COALESCE(AVG(rating), 5.0) as avg_rating
            FROM reviews WHERE product_id = %s
        """, (product_id,))
        review_stats = cursor.fetchone()
        prod_dict["rating"] = round(float(review_stats["avg_rating"]), 1) if review_stats else 5.0
        prod_dict["reviewsCount"] = int(review_stats["reviews_count"]) if review_stats else 0

        return jsonify({"success": True, "product": prod_dict}), 200
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# PRODUCT RATINGS & REVIEWS
# ==========================================================

@products_bp.route("/products/<int:product_id>/reviews", methods=["GET"])
def get_product_reviews(product_id):
    """Retrieve customer reviews, breakdown, and average rating for a product."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check product exists
        cursor.execute("SELECT id, name FROM products WHERE id = %s AND is_active = TRUE", (product_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Product not found"}), 404

        # Fetch reviews with user info (only approved reviews on storefront)
        cursor.execute("""
            SELECT r.id, r.product_id, r.user_id, r.rating, r.review_text, 
                   r.is_verified_purchase, r.status, r.admin_reply, r.admin_reply_at, r.created_at,
                   u.name as user_name, u.email as user_email
            FROM reviews r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.product_id = %s AND (r.status = 'approved' OR r.status IS NULL)
            ORDER BY r.created_at DESC, r.id DESC
        """, (product_id,))
        rows = cursor.fetchall()

        reviews = []
        total_rating = 0
        breakdown = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}

        for r in rows:
            star = max(1, min(5, int(r["rating"])))
            breakdown[star] = breakdown.get(star, 0) + 1
            total_rating += star

            # Format reviewer initials / display name
            raw_name = r["user_name"] or (r["user_email"].split("@")[0] if r.get("user_email") else "Verified Shopper")
            reviews.append({
                "id": r["id"],
                "product_id": r["product_id"],
                "user_id": r["user_id"],
                "user_name": raw_name,
                "rating": star,
                "review_text": r["review_text"] or "",
                "is_verified_purchase": bool(r.get("is_verified_purchase")),
                "admin_reply": r.get("admin_reply"),
                "admin_reply_at": str(r["admin_reply_at"])[:10] if r.get("admin_reply_at") else None,
                "created_at": str(r["created_at"])[:10] if r.get("created_at") else "Recent"
            })

        total_reviews = len(reviews)
        avg_rating = round(total_rating / total_reviews, 1) if total_reviews > 0 else 5.0

        return jsonify({
            "success": True,
            "reviews": reviews,
            "total_reviews": total_reviews,
            "average_rating": avg_rating,
            "breakdown": breakdown
        }), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/products/<int:product_id>/reviews", methods=["POST"])
@jwt_required()
def submit_product_review(product_id):
    """Submit or update a customer rating and review for a product."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json(silent=True) or {}
    try:
        rating = int(data.get("rating"))
        if rating < 1 or rating > 5:
            return jsonify({"success": False, "error": "Rating must be an integer between 1 and 5"}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Please provide a valid rating (1 to 5 stars)"}), 400

    review_text = (data.get("review_text") or "").strip()
    if not review_text or len(review_text) < 3:
        return jsonify({"success": False, "error": "Review comments must be at least 3 characters long"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check product exists
        cursor.execute("SELECT id FROM products WHERE id = %s", (product_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Product not found"}), 404

        # Check if user previously purchased product (Verified Buyer badge)
        cursor.execute("""
            SELECT 1 FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            WHERE oi.product_id = %s AND o.user_id = %s AND UPPER(o.status) != 'CANCELLED'
            LIMIT 1
        """, (product_id, user_id))
        is_verified = cursor.fetchone() is not None

        # Check if duplicate review already exists
        cursor.execute("SELECT id FROM reviews WHERE product_id = %s AND user_id = %s", (product_id, user_id))
        existing = cursor.fetchone()

        if existing:
            # Update existing review
            cursor.execute("""
                UPDATE reviews 
                SET rating = %s, review_text = %s, is_verified_purchase = %s
                WHERE id = %s
            """, (rating, review_text, is_verified, existing["id"]))
            conn.commit()
            return jsonify({
                "success": True,
                "message": "Your review has been updated successfully!",
                "review_id": existing["id"],
                "is_verified": is_verified
            }), 200
        else:
            # Insert new review
            cursor.execute("""
                INSERT INTO reviews (product_id, user_id, rating, review_text, is_verified_purchase)
                VALUES (%s, %s, %s, %s, %s)
            """, (product_id, user_id, rating, review_text, is_verified))
            conn.commit()
            new_id = cursor.lastrowid if is_mysql(conn) else None
            return jsonify({
                "success": True,
                "message": "Thank you! Your review has been published.",
                "review_id": new_id,
                "is_verified": is_verified
            }), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error submitting review: {e}")
        return jsonify({"success": False, "error": "Failed to submit review"}), 500
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/products/<int:product_id>/reviews/<int:review_id>", methods=["DELETE"])
@jwt_required()
def delete_product_review(product_id, review_id):
    """Delete a review if owned by user or admin."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    role = identity.get("role")

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, user_id FROM reviews WHERE id = %s AND product_id = %s", (review_id, product_id))
        review = cursor.fetchone()
        if not review:
            return jsonify({"success": False, "error": "Review not found"}), 404

        if review["user_id"] != user_id and role != "admin":
            return jsonify({"success": False, "error": "You do not have permission to delete this review"}), 403

        cursor.execute("DELETE FROM reviews WHERE id = %s", (review_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Review deleted successfully"}), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/products/deals", methods=["GET"])
def get_deals():
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT p.id, p.name, p.slug, p.description, p.price, p.discount_price,
                   p.stock, p.sku, p.brand, c.name as category_name,
                   (
                       SELECT image_url FROM product_images pi 
                       WHERE pi.product_id = p.id 
                       ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                   ) as image
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.is_active = TRUE AND p.discount_price IS NOT NULL AND p.discount_price < p.price
            ORDER BY (p.price - p.discount_price) DESC
            LIMIT 6
        """)
        deals = [dict(d) for d in cursor.fetchall()]
        for d in deals:
            d["price"] = float(d["price"])
            d["discount_price"] = float(d["discount_price"]) if d.get("discount_price") else None
            d["image"] = d.get("image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80"
            d["inStock"] = d.get("stock", 0) > 0
            d["badge"] = "Deal of the Day"
            d["rating"] = 4.8
            d["reviewsCount"] = 124
        return jsonify({"success": True, "deals": deals}), 200
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# ADMIN PRODUCT CRUD & INVENTORY
# ==========================================================

@products_bp.route("/admin/products", methods=["GET"])
@admin_required
def get_admin_products():
    """Admin product catalog listing with search, category filtering, and pagination."""
    q = request.args.get("q", "").strip()
    category_id = request.args.get("category_id")
    status = request.args.get("status", "all")
    page = max(1, int(request.args.get("page", 1)))
    limit = max(1, min(50, int(request.args.get("limit", 15))))
    offset = (page - 1) * limit

    conditions = []
    params = []

    if q:
        conditions.append("(LOWER(p.name) LIKE %s OR LOWER(p.sku) LIKE %s OR LOWER(p.brand) LIKE %s)")
        q_wild = f"%{q.lower()}%"
        params.extend([q_wild, q_wild, q_wild])

    if category_id and category_id != "all":
        conditions.append("p.category_id = %s")
        params.append(category_id)

    if status == "active":
        conditions.append("p.is_active = TRUE")
    elif status == "inactive":
        conditions.append("p.is_active = FALSE")

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Count total
        cursor.execute(f"SELECT COUNT(*) as total FROM products p {where_clause}", tuple(params))
        res = cursor.fetchone()
        total = res["total"] if isinstance(res, dict) else res[0]

        # Fetch products
        query = f"""
            SELECT p.id, p.name, p.slug, p.category_id, p.description, 
                   p.price, p.discount_price, p.stock, p.sku, p.brand, 
                   p.is_active, p.created_at,
                   c.name as category_name,
                   (
                       SELECT image_url FROM product_images pi 
                       WHERE pi.product_id = p.id 
                       ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                   ) as image
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            {where_clause}
            ORDER BY p.id DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        products = []
        for r in rows:
            price = float(r["price"]) if r.get("price") is not None else 0.0
            disc = float(r["discount_price"]) if r.get("discount_price") is not None else None
            products.append({
                "id": r["id"],
                "name": r["name"],
                "slug": r["slug"],
                "category_id": r["category_id"],
                "category_name": r["category_name"] or "Uncategorized",
                "description": r["description"] or "",
                "price": price,
                "discount_price": disc,
                "stock": int(r["stock"]),
                "sku": r["sku"],
                "brand": r["brand"],
                "is_active": bool(r["is_active"]),
                "image": r["image"] or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80",
                "created_at": str(r["created_at"]) if r.get("created_at") else None
            })

        total_pages = max(1, (total + limit - 1) // limit)
        return jsonify({
            "success": True,
            "products": products,
            "total": total,
            "page": page,
            "total_pages": total_pages
        }), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/products/<int:product_id>/toggle-status", methods=["PATCH"])
@admin_required
def toggle_product_status(product_id):
    """Toggle active/inactive status of a product."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, is_active, name FROM products WHERE id=%s", (product_id,))
        prod = cursor.fetchone()
        if not prod:
            return jsonify({"success": False, "error": "Product not found"}), 404

        new_status = not bool(prod["is_active"])
        cursor.execute("UPDATE products SET is_active = %s WHERE id = %s", (new_status, product_id))
        conn.commit()

        status_text = "activated" if new_status else "deactivated"
        return jsonify({
            "success": True, 
            "is_active": new_status,
            "message": f"Product '{prod['name']}' has been {status_text}."
        }), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/products", methods=["POST"])
@admin_required
def create_product():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    category_id = data.get("category_id")
    price = data.get("price")
    discount_price = data.get("discount_price")
    stock = data.get("stock", 0)
    sku = data.get("sku", "").strip()
    brand = data.get("brand", "").strip()
    description = data.get("description", "").strip()
    images = data.get("images", [])

    if not name or price is None:
        return jsonify({"success": False, "error": "Name and price are required"}), 400

    try:
        price = float(price)
        if price <= 0:
            return jsonify({"success": False, "error": "Price must be greater than 0"}), 400
        discount_price = float(discount_price) if discount_price not in (None, "") else None
        if discount_price is not None and discount_price >= price:
            return jsonify({"success": False, "error": "Discount price must be less than regular price"}), 400
        stock = max(0, int(stock))
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid numerical values for price or stock"}), 400

    if not sku:
        sku = "SKU-" + secrets.token_hex(4).upper()

    slug = slugify(name) + "-" + secrets.token_hex(2)

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            INSERT INTO products (name, slug, category_id, description, price, discount_price, stock, sku, brand, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
        """, (name, slug, category_id, description, price, discount_price, stock, sku, brand))

        product_id = cursor.lastrowid if is_mysql(conn) else None
        if not product_id:
            cursor.execute("SELECT id FROM products WHERE sku=%s", (sku,))
            row = cursor.fetchone()
            product_id = row["id"] if row else None

        # Insert primary image if provided
        if images and isinstance(images, list) and product_id:
            for idx, img_url in enumerate(images):
                if img_url and isinstance(img_url, str):
                    cursor.execute("""
                        INSERT INTO product_images (product_id, image_url, is_primary)
                        VALUES (%s, %s, %s)
                    """, (product_id, img_url.strip(), idx == 0))

        # Log initial inventory
        if product_id:
            cursor.execute("""
                INSERT INTO inventory_logs (product_id, change_type, quantity_changed, remaining_stock, notes)
                VALUES (%s, 'initial_stock', %s, %s, 'Product created')
            """, (product_id, stock, stock))

        conn.commit()
        return jsonify({
            "success": True, 
            "message": "Product created successfully",
            "product_id": product_id,
            "sku": sku
        }), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error creating product: {e}")
        return jsonify({"success": False, "error": "Failed to create product in database"}), 500
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/products/<int:product_id>", methods=["PUT"])
@admin_required
def update_product(product_id):
    data = request.get_json(silent=True) or {}
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, stock FROM products WHERE id=%s", (product_id,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({"success": False, "error": "Product not found"}), 404

        fields = []
        params = []

        if "name" in data:
            fields.append("name = %s")
            params.append(data["name"].strip())
        if "category_id" in data:
            fields.append("category_id = %s")
            params.append(data["category_id"])
        if "description" in data:
            fields.append("description = %s")
            params.append(data["description"].strip())
        if "brand" in data:
            fields.append("brand = %s")
            params.append(data["brand"].strip())
        if "is_active" in data:
            fields.append("is_active = %s")
            params.append(bool(data["is_active"]))
        if "price" in data:
            p = float(data["price"])
            if p <= 0:
                return jsonify({"success": False, "error": "Price must be positive"}), 400
            fields.append("price = %s")
            params.append(p)
        if "discount_price" in data:
            dp = float(data["discount_price"]) if data["discount_price"] not in (None, "") else None
            fields.append("discount_price = %s")
            params.append(dp)
        if "stock" in data:
            new_stock = max(0, int(data["stock"]))
            fields.append("stock = %s")
            params.append(new_stock)
            # Log stock adjustment
            old_stock = existing["stock"]
            cursor.execute("""
                INSERT INTO inventory_logs (product_id, change_type, quantity_changed, remaining_stock, notes)
                VALUES (%s, 'manual_adjustment', %s, %s, 'Admin updated stock')
            """, (product_id, new_stock - old_stock, new_stock))

        if fields:
            params.append(product_id)
            cursor.execute(f"UPDATE products SET {', '.join(fields)} WHERE id=%s", tuple(params))
            conn.commit()

        return jsonify({"success": True, "message": "Product updated successfully"}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating product: {e}")
        return jsonify({"success": False, "error": "Failed to update product"}), 500
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/products/<int:product_id>", methods=["DELETE"])
@admin_required
def delete_product(product_id):
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id FROM products WHERE id=%s", (product_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Product not found"}), 404

        # Soft delete by marking inactive to preserve order history
        cursor.execute("UPDATE products SET is_active=FALSE WHERE id=%s", (product_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Product deleted successfully"}), 200
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# ADMIN INVENTORY MANAGEMENT & LOGS
# ==========================================================

@products_bp.route("/admin/inventory", methods=["GET"])
@admin_required
def admin_get_inventory():
    """Retrieve catalog inventory status, metrics, and stock level controls."""
    q = request.args.get("q", "").strip()
    stock_status = request.args.get("stock_status", "all").strip().lower()
    page = max(1, int(request.args.get("page", 1)))
    limit = max(1, min(100, int(request.args.get("limit", 15))))
    offset = (page - 1) * limit

    conditions = []
    params = []

    if q:
        conditions.append("(LOWER(p.name) LIKE %s OR LOWER(p.sku) LIKE %s)")
        q_wild = f"%{q.lower()}%"
        params.extend([q_wild, q_wild])

    if stock_status == "low":
        conditions.append("p.stock > 0 AND p.stock <= 10")
    elif stock_status == "out":
        conditions.append("p.stock = 0")
    elif stock_status == "healthy":
        conditions.append("p.stock > 10")

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Aggregation metrics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_products,
                SUM(CASE WHEN stock <= 10 AND stock > 0 THEN 1 ELSE 0 END) as low_stock_count,
                SUM(CASE WHEN stock = 0 THEN 1 ELSE 0 END) as out_of_stock_count,
                COALESCE(SUM(stock), 0) as total_units
            FROM products
        """)
        metrics_row = cursor.fetchone() or {}
        metrics = {
            "total_products": int(metrics_row.get("total_products") or 0),
            "low_stock_count": int(metrics_row.get("low_stock_count") or 0),
            "out_of_stock_count": int(metrics_row.get("out_of_stock_count") or 0),
            "total_units": int(metrics_row.get("total_units") or 0)
        }

        # Filtered count
        cursor.execute(f"SELECT COUNT(*) as filtered_total FROM products p {where_clause}", tuple(params))
        total_filtered = cursor.fetchone()["filtered_total"]

        # Inventory page
        query = f"""
            SELECT p.id, p.name, p.sku, p.stock, p.price, p.discount_price, 
                   p.is_active, p.created_at, p.updated_at,
                   c.name as category_name,
                   (
                       SELECT image_url FROM product_images pi 
                       WHERE pi.product_id = p.id 
                       ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                   ) as image
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            {where_clause}
            ORDER BY p.stock ASC, p.id DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        items = []
        for r in rows:
            items.append({
                "id": r["id"],
                "name": r["name"],
                "sku": r["sku"] or f"SKU-{r['id']}",
                "category_name": r["category_name"] or "Uncategorized",
                "stock": int(r["stock"]),
                "price": float(r["price"]),
                "is_active": bool(r["is_active"]),
                "image": r.get("image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80"
            })

        total_pages = max(1, (total_filtered + limit - 1) // limit)
        return jsonify({
            "success": True,
            "items": items,
            "metrics": metrics,
            "total": total_filtered,
            "page": page,
            "total_pages": total_pages
        }), 200
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/inventory/adjust", methods=["POST"])
@admin_required
def admin_adjust_inventory():
    """Adjust product stock quantity with audit logging."""
    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    adj_type = (data.get("adjustment_type") or "SET").upper()
    try:
        qty = int(data.get("quantity", 0))
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid quantity number"}), 400

    reason = (data.get("reason") or "Manual inventory adjustment").strip()

    if not product_id:
        return jsonify({"success": False, "error": "product_id is required"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, name, sku, stock FROM products WHERE id = %s", (product_id,))
        prod = cursor.fetchone()
        if not prod:
            return jsonify({"success": False, "error": "Product not found"}), 404

        old_stock = int(prod["stock"])
        if adj_type == "ADD":
            new_stock = old_stock + qty
            qty_changed = qty
        else: # SET
            new_stock = qty
            qty_changed = new_stock - old_stock

        if new_stock < 0:
            return jsonify({"success": False, "error": "Stock level cannot be less than 0"}), 400

        # Update product stock
        cursor.execute("UPDATE products SET stock = %s WHERE id = %s", (new_stock, product_id))

        # Log change in inventory_logs
        cursor.execute("""
            INSERT INTO inventory_logs (product_id, change_type, quantity_changed, remaining_stock, notes)
            VALUES (%s, %s, %s, %s, %s)
        """, (product_id, f"MANUAL_{adj_type}", qty_changed, new_stock, reason))

        conn.commit()

        return jsonify({
            "success": True,
            "product_id": product_id,
            "product_name": prod["name"],
            "old_stock": old_stock,
            "new_stock": new_stock,
            "message": f"Stock for '{prod['name']}' updated from {old_stock} to {new_stock}."
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adjusting inventory: {e}")
        return jsonify({"success": False, "error": "Failed to update stock"}), 500
    finally:
        cursor.close()
        conn.close()

@products_bp.route("/admin/inventory/logs", methods=["GET"])
@admin_required
def admin_get_inventory_logs():
    """Retrieve historical audit logs of stock alterations."""
    product_id = request.args.get("product_id")
    page = max(1, int(request.args.get("page", 1)))
    limit = max(1, min(100, int(request.args.get("limit", 20))))
    offset = (page - 1) * limit

    conditions = []
    params = []

    if product_id:
        conditions.append("il.product_id = %s")
        params.append(product_id)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute(f"SELECT COUNT(*) as total FROM inventory_logs il {where_clause}", tuple(params))
        total = cursor.fetchone()["total"]

        query = f"""
            SELECT il.id, il.product_id, il.change_type, il.quantity_changed, 
                   il.remaining_stock, il.notes, il.created_at,
                   p.name as product_name, p.sku as product_sku
            FROM inventory_logs il
            LEFT JOIN products p ON il.product_id = p.id
            {where_clause}
            ORDER BY il.created_at DESC, il.id DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        logs = []
        for r in rows:
            logs.append({
                "id": r["id"],
                "product_id": r["product_id"],
                "product_name": r["product_name"] or "Unknown Product",
                "sku": r["product_sku"] or "N/A",
                "change_type": r["change_type"],
                "quantity_changed": int(r["quantity_changed"]),
                "remaining_stock": int(r["remaining_stock"]),
                "notes": r["notes"] or "",
                "created_at": str(r["created_at"]) if r.get("created_at") else None
            })

        total_pages = max(1, (total + limit - 1) // limit)
        return jsonify({
            "success": True,
            "logs": logs,
            "total": total,
            "page": page,
            "total_pages": total_pages
        }), 200
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# INITIAL DEMO SEEDING HELPER
# ==========================================================

def seed_catalog(conn):
    """Seed initial categories and products if tables are empty."""
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT COUNT(*) as count FROM categories")
        res = cursor.fetchone()
        count = res["count"] if isinstance(res, dict) else res[0]
        if count > 0:
            return

        initial_categories = [
            ("Electronics", "electronics", "High-performance tech and audio devices", "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=400&q=80"),
            ("Fashion", "fashion", "Minimalist, organic and designer apparel", "https://images.unsplash.com/photo-1576566588028-4147f3842f27?auto=format&fit=crop&w=400&q=80"),
            ("Home & Living", "home", "Modern appliances and lifestyle decor", "https://images.unsplash.com/photo-1570968915860-54d5c301fa9f?auto=format&fit=crop&w=400&q=80"),
            ("Beauty & Personal Care", "beauty", "Botanical formulas and clean skincare", "https://images.unsplash.com/photo-1620916566398-39f1143ab7be?auto=format&fit=crop&w=400&q=80"),
            ("Sports & Outdoors", "sports", "Ergonomic workout and outdoor adventure gear", "https://images.unsplash.com/photo-1517838277536-f5f99be501cd?auto=format&fit=crop&w=400&q=80"),
        ]

        cat_ids = {}
        for name, slug, desc, img in initial_categories:
            cursor.execute("""
                INSERT INTO categories (name, slug, description, image_url, is_active)
                VALUES (%s, %s, %s, %s, TRUE)
            """, (name, slug, desc, img))
            cid = cursor.lastrowid if is_mysql(conn) else None
            if not cid:
                cursor.execute("SELECT id FROM categories WHERE slug=%s", (slug,))
                r = cursor.fetchone()
                cid = r["id"] if r else None
            cat_ids[slug] = cid

        initial_products = [
            ("AeroPulse Wireless Noise-Cancelling Headphones", "aeropulse-wireless-headphones", cat_ids.get("electronics"), 
             "Ultra-low latency audio with adaptive hybrid noise cancellation and 40-hour playtime.", 189.99, 149.99, 45, "SKU-AUDIO-01", "AeroPulse",
             "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80"),
            
            ("Titan Chrono Smartwatch Ultra with Titanium Frame", "titan-chrono-smartwatch", cat_ids.get("electronics"),
             "Precision sapphire glass, ECG monitoring, cellular standby, and waterproof up to 50 meters.", 299.00, 249.00, 28, "SKU-WATCH-02", "Titan",
             "https://images.unsplash.com/photo-1523275335684-37898b6baf30?auto=format&fit=crop&w=600&q=80"),

            ("Merino Wool Minimalist Knit Sweater", "merino-wool-knit-sweater", cat_ids.get("fashion"),
             "Superfine 100% natural merino wool offering supreme breathability and modern tailored fit.", 79.50, None, 60, "SKU-APPAREL-03", "Aura",
             "https://images.unsplash.com/photo-1576566588028-4147f3842f27?auto=format&fit=crop&w=600&q=80"),

            ("Precision Barista Espresso Machine with Steam Wand", "barista-espresso-machine", cat_ids.get("home"),
             "15-bar Italian pump with integrated thermo-coil system and micro-foam milk texturing.", 449.99, 399.99, 15, "SKU-KITCHEN-04", "BrewMaster",
             "https://images.unsplash.com/photo-1570968915860-54d5c301fa9f?auto=format&fit=crop&w=600&q=80"),

            ("HydraGlow Botanical Facial Serum Complex", "hydraglow-botanical-serum", cat_ids.get("beauty"),
             "Formulated with cold-pressed rosehip seed oil, hyaluronic acid, and niacinamide for radiant skin.", 42.00, 34.00, 80, "SKU-SERUM-05", "GlowLab",
             "https://images.unsplash.com/photo-1620916566398-39f1143ab7be?auto=format&fit=crop&w=600&q=80"),

            ("CarbonFiber Ultralight Ergonomic Mechanical Keyboard", "carbonfiber-mechanical-keyboard", cat_ids.get("electronics"),
             "Hot-swappable custom lubricated switches, wireless multi-device pairing, and RGB underglow.", 139.00, None, 35, "SKU-KEY-06", "ApexType",
             "https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=600&q=80"),
        ]

        for name, slug, cid, desc, price, disc, stock, sku, brand, img in initial_products:
            cursor.execute("""
                INSERT INTO products (name, slug, category_id, description, price, discount_price, stock, sku, brand, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
            """, (name, slug, cid, desc, price, disc, stock, sku, brand))
            pid = cursor.lastrowid if is_mysql(conn) else None
            if not pid:
                cursor.execute("SELECT id FROM products WHERE sku=%s", (sku,))
                pr = cursor.fetchone()
                pid = pr["id"] if pr else None
            if pid:
                cursor.execute("""
                    INSERT INTO product_images (product_id, image_url, is_primary)
                    VALUES (%s, %s, TRUE)
                """, (pid, img))
                cursor.execute("""
                    INSERT INTO inventory_logs (product_id, change_type, quantity_changed, remaining_stock, notes)
                    VALUES (%s, 'initial_seed', %s, %s, 'System catalog seed')
                """, (pid, stock, stock))

        conn.commit()
        logging.info("Seeded initial categories and products successfully.")
    except Exception as e:
        conn.rollback()
        logging.warning(f"Could not seed initial catalog: {e}")
    finally:
        cursor.close()
