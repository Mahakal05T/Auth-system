import logging
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor

reviews_bp = Blueprint('reviews', __name__)

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ==========================================================
# ADMIN PRODUCT REVIEWS MODERATION API
# ==========================================================

@reviews_bp.route("/admin/reviews", methods=["GET"])
@admin_required
def admin_get_reviews():
    """Fetch paginated customer reviews with KPIs, star filtering, and moderation status."""
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "all").lower()
    rating_filter = request.args.get("rating", "all")
    verified_filter = request.args.get("verified", "all")
    page = max(1, request.args.get("page", 1, type=int))
    limit = min(50, max(5, request.args.get("limit", 15, type=int)))
    offset = (page - 1) * limit

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # 1. Overall review metrics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_reviews,
                SUM(CASE WHEN status = 'approved' OR status IS NULL THEN 1 ELSE 0 END) as approved_reviews,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_reviews,
                SUM(CASE WHEN status = 'hidden' THEN 1 ELSE 0 END) as hidden_reviews,
                SUM(CASE WHEN is_verified_purchase = TRUE THEN 1 ELSE 0 END) as verified_reviews,
                COALESCE(AVG(rating), 5.0) as average_rating,
                SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) as stars_5,
                SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) as stars_4,
                SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as stars_3,
                SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) as stars_2,
                SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as stars_1
            FROM reviews
        """)
        stats_row = cursor.fetchone() or {}
        
        stats = {
            "total_reviews": int(stats_row.get("total_reviews") or 0),
            "approved_reviews": int(stats_row.get("approved_reviews") or 0),
            "pending_reviews": int(stats_row.get("pending_reviews") or 0),
            "hidden_reviews": int(stats_row.get("hidden_reviews") or 0),
            "verified_reviews": int(stats_row.get("verified_reviews") or 0),
            "average_rating": round(float(stats_row.get("average_rating") or 5.0), 2),
            "rating_distribution": {
                5: int(stats_row.get("stars_5") or 0),
                4: int(stats_row.get("stars_4") or 0),
                3: int(stats_row.get("stars_3") or 0),
                2: int(stats_row.get("stars_2") or 0),
                1: int(stats_row.get("stars_1") or 0),
            }
        }

        # 2. Build filtered review query
        conditions = []
        params = []

        if search:
            conditions.append("(u.name LIKE %s OR u.email LIKE %s OR p.name LIKE %s OR r.review_text LIKE %s)")
            wildcard = f"%{search}%"
            params.extend([wildcard, wildcard, wildcard, wildcard])

        if status_filter in ("approved", "pending", "hidden"):
            if status_filter == "approved":
                conditions.append("(r.status = 'approved' OR r.status IS NULL)")
            else:
                conditions.append("r.status = %s")
                params.append(status_filter)

        if rating_filter.isdigit():
            star = int(rating_filter)
            if 1 <= star <= 5:
                conditions.append("r.rating = %s")
                params.append(star)

        if verified_filter == "true":
            conditions.append("r.is_verified_purchase = TRUE")
        elif verified_filter == "false":
            conditions.append("r.is_verified_purchase = FALSE")

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # Total matching
        count_sql = f"""
            SELECT COUNT(*) as count 
            FROM reviews r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN products p ON r.product_id = p.id
            {where_clause}
        """
        cursor.execute(count_sql, tuple(params))
        total_matching = cursor.fetchone()["count"]

        # Paginated fetch
        fetch_sql = f"""
            SELECT 
                r.id, r.product_id, r.user_id, r.rating, r.review_text,
                r.is_verified_purchase, COALESCE(r.status, 'approved') as status,
                r.admin_reply, r.admin_reply_at, r.created_at, r.updated_at,
                u.name as user_name, u.email as user_email,
                p.name as product_name, p.slug as product_slug,
                (
                    SELECT image_url FROM product_images pi 
                    WHERE pi.product_id = p.id 
                    ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                ) as product_image
            FROM reviews r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN products p ON r.product_id = p.id
            {where_clause}
            ORDER BY r.created_at DESC, r.id DESC
            LIMIT %s OFFSET %s
        """
        fetch_params = params + [limit, offset]
        cursor.execute(fetch_sql, tuple(fetch_params))
        rows = cursor.fetchall()

        reviews_list = []
        for r in rows:
            reviews_list.append({
                "id": r["id"],
                "product_id": r["product_id"],
                "product_name": r.get("product_name") or "Unknown Product",
                "product_slug": r.get("product_slug") or "",
                "product_image": r.get("product_image") or "",
                "user_id": r["user_id"],
                "user_name": r.get("user_name") or (r["user_email"].split("@")[0] if r.get("user_email") else "Shopper"),
                "user_email": r.get("user_email") or "",
                "rating": int(r["rating"]),
                "review_text": r.get("review_text") or "",
                "is_verified_purchase": bool(r.get("is_verified_purchase")),
                "status": r.get("status") or "approved",
                "admin_reply": r.get("admin_reply"),
                "admin_reply_at": r["admin_reply_at"].isoformat() if r.get("admin_reply_at") else None,
                "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
            })

        total_pages = max(1, (total_matching + limit - 1) // limit)

        return jsonify({
            "success": True,
            "reviews": reviews_list,
            "total": total_matching,
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "stats": stats
        }), 200
    except Exception as e:
        logging.error(f"Error fetching admin reviews: {e}")
        return jsonify({"success": False, "error": "Failed to fetch reviews"}), 500
    finally:
        cursor.close()
        conn.close()

@reviews_bp.route("/admin/reviews/<int:review_id>/status", methods=["PATCH"])
@admin_required
def update_review_status(review_id):
    """Change review moderation status: approved, pending, or hidden."""
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "").strip().lower()
    if new_status not in ("approved", "pending", "hidden"):
        return jsonify({"success": False, "error": "Invalid status. Must be 'approved', 'pending', or 'hidden'"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, status FROM reviews WHERE id = %s", (review_id,))
        review = cursor.fetchone()
        if not review:
            return jsonify({"success": False, "error": "Review not found"}), 404

        cursor.execute("UPDATE reviews SET status = %s WHERE id = %s", (new_status, review_id))
        conn.commit()

        status_messages = {
            "approved": "Review approved and now live on storefront.",
            "hidden": "Review hidden from storefront.",
            "pending": "Review moved to pending moderation queue."
        }

        return jsonify({
            "success": True,
            "message": status_messages.get(new_status, "Status updated"),
            "status": new_status
        }), 200
    finally:
        cursor.close()
        conn.close()

@reviews_bp.route("/admin/reviews/<int:review_id>/reply", methods=["POST"])
@admin_required
def reply_to_review(review_id):
    """Post an official seller/store reply to a customer review."""
    data = request.get_json(silent=True) or {}
    reply_text = (data.get("reply_text") or "").strip()
    if not reply_text:
        return jsonify({"success": False, "error": "Reply comment cannot be empty"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id FROM reviews WHERE id = %s", (review_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Review not found"}), 404

        now = datetime.utcnow()
        cursor.execute("""
            UPDATE reviews 
            SET admin_reply = %s, admin_reply_at = %s 
            WHERE id = %s
        """, (reply_text, now, review_id))
        conn.commit()

        return jsonify({
            "success": True,
            "message": "Official response posted successfully.",
            "admin_reply": reply_text,
            "admin_reply_at": now.isoformat()
        }), 200
    finally:
        cursor.close()
        conn.close()

@reviews_bp.route("/admin/reviews/<int:review_id>/reply", methods=["DELETE"])
@admin_required
def delete_review_reply(review_id):
    """Remove official store reply from a review."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id FROM reviews WHERE id = %s", (review_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Review not found"}), 404

        cursor.execute("UPDATE reviews SET admin_reply = NULL, admin_reply_at = NULL WHERE id = %s", (review_id,))
        conn.commit()

        return jsonify({"success": True, "message": "Official response removed."}), 200
    finally:
        cursor.close()
        conn.close()

@reviews_bp.route("/admin/reviews/<int:review_id>", methods=["DELETE"])
@admin_required
def admin_delete_review(review_id):
    """Permanently delete a customer review."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id FROM reviews WHERE id = %s", (review_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Review not found"}), 404

        cursor.execute("DELETE FROM reviews WHERE id = %s", (review_id,))
        conn.commit()

        return jsonify({"success": True, "message": "Review permanently deleted."}), 200
    finally:
        cursor.close()
        conn.close()
