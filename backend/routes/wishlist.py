import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor, is_mysql

wishlist_bp = Blueprint('wishlist', __name__, url_prefix='/wishlist')

def get_or_create_user_wishlist(cursor, conn, user_id):
    """Retrieve or insert a customer wishlist."""
    cursor.execute("SELECT id FROM wishlist WHERE user_id = %s LIMIT 1", (user_id,))
    row = cursor.fetchone()
    if row:
        return row["id"]

    cursor.execute("INSERT INTO wishlist (user_id) VALUES (%s)", (user_id,))
    wishlist_id = cursor.lastrowid if is_mysql(conn) else None
    if not wishlist_id:
        cursor.execute("SELECT id FROM wishlist WHERE user_id = %s", (user_id,))
        r = cursor.fetchone()
        wishlist_id = r["id"] if r else None
    conn.commit()
    return wishlist_id

def get_wishlist_details(cursor, wishlist_id):
    """Fetch wishlist items with product metadata and primary image."""
    cursor.execute("""
        SELECT wi.id as item_id, wi.product_id, wi.created_at,
               p.name, p.price, p.discount_price, p.stock, p.sku, p.brand, p.is_active,
               c.name as category_name, c.slug as category_slug,
               (
                   SELECT image_url FROM product_images pi 
                   WHERE pi.product_id = p.id 
                   ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
               ) as image
        FROM wishlist_items wi
        JOIN products p ON wi.product_id = p.id
        LEFT JOIN categories c ON p.category_id = c.id
        WHERE wi.wishlist_id = %s
        ORDER BY wi.id DESC
    """, (wishlist_id,))
    rows = cursor.fetchall()

    items = []
    for r in rows:
        price = float(r["price"]) if r.get("price") is not None else 0.0
        disc_price = float(r["discount_price"]) if r.get("discount_price") is not None else None
        current_price = disc_price if (disc_price is not None and 0 < disc_price < price) else price

        items.append({
            "id": r["item_id"],
            "product_id": r["product_id"],
            "name": r["name"],
            "category": r["category_name"] or "General",
            "category_slug": r["category_slug"],
            "brand": r["brand"],
            "sku": r["sku"],
            "image": r["image"] or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80",
            "price": round(current_price, 2),
            "original_price": round(price, 2) if disc_price else None,
            "stock": int(r.get("stock", 0)),
            "in_stock": int(r.get("stock", 0)) > 0,
            "is_active": bool(r.get("is_active", True))
        })

    return {
        "wishlist_id": wishlist_id,
        "items": items,
        "total_items": len(items)
    }

# ==========================================================
# WISHLIST ENDPOINTS
# ==========================================================

@wishlist_bp.route("", methods=["GET"])
@jwt_required()
def get_wishlist():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        wishlist_id = get_or_create_user_wishlist(cursor, conn, user_id)
        summary = get_wishlist_details(cursor, wishlist_id)
        return jsonify({"success": True, "wishlist": summary}), 200
    except Exception as e:
        logging.error(f"Error fetching wishlist: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve wishlist"}), 500
    finally:
        cursor.close()
        conn.close()

@wishlist_bp.route("/items", methods=["POST"])
@jwt_required()
def add_to_wishlist():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    if not product_id:
        return jsonify({"success": False, "error": "Product ID is required"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check product existence
        cursor.execute("SELECT id, name FROM products WHERE id = %s AND is_active = TRUE", (product_id,))
        prod = cursor.fetchone()
        if not prod:
            return jsonify({"success": False, "error": "Product not found"}), 404

        wishlist_id = get_or_create_user_wishlist(cursor, conn, user_id)

        # Check if item is already in wishlist
        cursor.execute("SELECT id FROM wishlist_items WHERE wishlist_id = %s AND product_id = %s", (wishlist_id, product_id))
        existing = cursor.fetchone()
        if not existing:
            cursor.execute("INSERT INTO wishlist_items (wishlist_id, product_id) VALUES (%s, %s)", (wishlist_id, product_id))
            conn.commit()

        summary = get_wishlist_details(cursor, wishlist_id)
        return jsonify({
            "success": True, 
            "message": f"Added {prod['name']} to wishlist",
            "in_wishlist": True,
            "wishlist": summary
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adding to wishlist: {e}")
        return jsonify({"success": False, "error": "Failed to add to wishlist"}), 500
    finally:
        cursor.close()
        conn.close()

@wishlist_bp.route("/items/<int:product_id>", methods=["DELETE"])
@jwt_required()
def remove_from_wishlist(product_id):
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        wishlist_id = get_or_create_user_wishlist(cursor, conn, user_id)
        # Delete by product_id or wishlist_items id
        cursor.execute("""
            DELETE FROM wishlist_items 
            WHERE wishlist_id = %s AND (product_id = %s OR id = %s)
        """, (wishlist_id, product_id, product_id))
        conn.commit()

        summary = get_wishlist_details(cursor, wishlist_id)
        return jsonify({
            "success": True, 
            "message": "Removed from wishlist",
            "in_wishlist": False,
            "wishlist": summary
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error removing from wishlist: {e}")
        return jsonify({"success": False, "error": "Failed to remove from wishlist"}), 500
    finally:
        cursor.close()
        conn.close()

@wishlist_bp.route("/move-to-cart", methods=["POST"])
@jwt_required()
def move_wishlist_to_cart():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    if not product_id:
        return jsonify({"success": False, "error": "Product ID is required"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check product and stock
        cursor.execute("SELECT id, name, stock, is_active FROM products WHERE id = %s", (product_id,))
        prod = cursor.fetchone()
        if not prod or not prod["is_active"]:
            return jsonify({"success": False, "error": "Product is not available"}), 404

        if prod["stock"] <= 0:
            return jsonify({"success": False, "error": "Product is currently out of stock"}), 400

        wishlist_id = get_or_create_user_wishlist(cursor, conn, user_id)

        # Get or create cart
        cursor.execute("SELECT id FROM cart WHERE user_id = %s LIMIT 1", (user_id,))
        cart_row = cursor.fetchone()
        if cart_row:
            cart_id = cart_row["id"]
        else:
            cursor.execute("INSERT INTO cart (user_id) VALUES (%s)", (user_id,))
            cart_id = cursor.lastrowid if is_mysql(conn) else None
            if not cart_id:
                cursor.execute("SELECT id FROM cart WHERE user_id = %s", (user_id,))
                cart_id = cursor.fetchone()["id"]

        # Insert or increment in cart
        cursor.execute("SELECT id, quantity FROM cart_items WHERE cart_id = %s AND product_id = %s", (cart_id, product_id))
        existing_cart_item = cursor.fetchone()
        if existing_cart_item:
            new_qty = min(prod["stock"], existing_cart_item["quantity"] + 1)
            cursor.execute("UPDATE cart_items SET quantity = %s WHERE id = %s", (new_qty, existing_cart_item["id"]))
        else:
            cursor.execute("INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (%s, %s, 1)", (cart_id, product_id))

        # Delete from wishlist
        cursor.execute("DELETE FROM wishlist_items WHERE wishlist_id = %s AND product_id = %s", (wishlist_id, product_id))
        conn.commit()

        wishlist_summary = get_wishlist_details(cursor, wishlist_id)
        return jsonify({
            "success": True, 
            "message": f"Moved {prod['name']} to cart",
            "wishlist": wishlist_summary
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error moving to cart: {e}")
        return jsonify({"success": False, "error": "Failed to move item to cart"}), 500
    finally:
        cursor.close()
        conn.close()

@wishlist_bp.route("/sync", methods=["POST"])
@jwt_required()
def sync_guest_wishlist():
    """Merge guest wishlist items into customer's persistent database wishlist."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    data = request.get_json(silent=True) or {}
    guest_items = data.get("items", [])

    if not isinstance(guest_items, list):
        return jsonify({"success": False, "error": "Items list expected"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        wishlist_id = get_or_create_user_wishlist(cursor, conn, user_id)

        for item in guest_items:
            product_id = item.get("product_id") or item.get("id")
            if not product_id:
                continue

            cursor.execute("SELECT id FROM products WHERE id = %s AND is_active = TRUE", (product_id,))
            if not cursor.fetchone():
                continue

            cursor.execute("SELECT id FROM wishlist_items WHERE wishlist_id = %s AND product_id = %s", (wishlist_id, product_id))
            if not cursor.fetchone():
                cursor.execute("INSERT INTO wishlist_items (wishlist_id, product_id) VALUES (%s, %s)", (wishlist_id, product_id))

        conn.commit()
        summary = get_wishlist_details(cursor, wishlist_id)
        return jsonify({"success": True, "wishlist": summary}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error syncing guest wishlist: {e}")
        return jsonify({"success": False, "error": "Failed to sync wishlist"}), 500
    finally:
        cursor.close()
        conn.close()
